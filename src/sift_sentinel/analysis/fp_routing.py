"""FP-verdict routing fixes (env-gated SIFT_FP_ROUTING) -- a pre-routing pass.

Two universal, conservative corrections the live run exposed:

  1. Loopback FP -- a ReAct benign verdict on a finding whose network scope is
     loopback-only (127.0.0.1 / ::1, no RFC1918 or external peer) must be honored.
     A "behavioral anomaly" (admin-share / egress) on loopback cannot be lateral
     movement or exfiltration, so the deterministic anomaly-hold must not override
     the benign verdict for it.

  2. Per-entity benign propagation -- if a process entity (pid / image) is judged
     benign by ReAct in ONE finding, other findings on the SAME entity that carry
     no INDEPENDENT (non weak-alone) malicious signal inherit the benign verdict.
     So the same process cannot read benign in one row and suspicious in another
     (e.g. a signed updater whose only other signal is a weak RWX region).

Both are conservative: propagation never overrides a finding that has its own
non-weak malicious-semantic signal or an explicit malicious ReAct verdict. The
pass only SETS a ``_fp_routing_benign`` flag; ``derive_final_disposition`` honors
it. The flag is only ever set when this (env-gated) pass runs, so default routing
is unchanged. Universal: keys on loopback/RFC1918 shape + pid/image identity +
the registered weak-alone signal set -- never a tool / case / host literal.
"""
from __future__ import annotations

import re

from sift_sentinel.analysis.disposition import (
    extract_react_verdict, has_malicious_semantic,
    _WEAK_ALONE_SEMANTIC_SIGNALS, _DISK_HISTORY_SEMANTIC_SIGNALS,
)

_V_BENIGN = "confirmed_benign"
_V_LIKELY_FP = "likely_fp"
_BENIGN_VERDICTS = frozenset({_V_BENIGN, _V_LIKELY_FP, "benign", "false_positive", "fp"})

_RFC1918 = re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b")
_LOOPBACK = re.compile(r"\b127\.0\.0\.1\b|::1\b|\blocalhost\b", re.I)
_PUBLIC_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PID = re.compile(r"\bpid[:=]?\s*(\d{1,7})\b", re.I)


def _text(finding: dict) -> str:
    parts = [str(finding.get(k) or "") for k in ("title", "description", "raw_excerpt")]
    for c in finding.get("claims") or []:
        if isinstance(c, dict):
            parts.append(" ".join(str(v) for v in c.values()))
    return " ".join(parts)


def loopback_only(finding: dict) -> bool:
    """True iff the finding's network scope is loopback only (no RFC1918/public peer)."""
    t = _text(finding)
    if not _LOOPBACK.search(t):
        return False
    if _RFC1918.search(t):
        return False
    # a non-loopback public IP present -> not loopback-only
    for m in _PUBLIC_IP.finditer(t):
        ip = m.group(0)
        if not ip.startswith("127.") and ip not in ("0.0.0.0",):
            return False
    return True


def _benign_verdict(finding: dict) -> bool:
    v, _ = extract_react_verdict(finding, None)
    rc = finding.get("react_conclusion")
    if isinstance(rc, dict) and rc.get("is_false_positive") is True:
        return True
    return str(v or "").strip().lower() in _BENIGN_VERDICTS


def _malicious_verdict(finding: dict) -> bool:
    v, _ = extract_react_verdict(finding, None)
    return str(v or "").strip().lower() in ("confirmed_malicious", "malicious")


def _entity_pids(finding: dict) -> set:
    pids = set()
    for c in finding.get("claims") or []:
        if isinstance(c, dict) and c.get("pid") not in (None, ""):
            pids.add(str(c.get("pid")).strip())
    for m in _PID.finditer(_text(finding)):
        pids.add(m.group(1))
    return {p for p in pids if p and p != "0"}


def has_independent_malice(finding: dict, evidence_db=None) -> bool:
    """The finding carries a malicious-semantic signal that is NOT weak-alone /
    disk-history -- i.e. its own standalone reason to be suspicious."""
    has_sem, sigs = has_malicious_semantic(finding, evidence_db)
    if not has_sem:
        return False
    fired = set(sigs)
    return bool(fired - _WEAK_ALONE_SEMANTIC_SIGNALS - _DISK_HISTORY_SEMANTIC_SIGNALS)


def _has_external_peer(finding: dict) -> bool:
    """True when the finding's own text/claims carry a PUBLIC external IPv4 --
    distinct network behavior a benign verdict on the same ENTITY never
    adjudicated. Octet shape only (loopback / RFC1918 / unspecified excluded);
    no process-name list. Kill-switch SIFT_FP_PROP_EGRESS_VETO=0."""
    import os
    if os.environ.get("SIFT_FP_PROP_EGRESS_VETO", "1") == "0":
        return False
    t = _text(finding)
    for m in _PUBLIC_IP.finditer(t):
        ip = m.group(0)
        if ip.startswith("127.") or ip == "0.0.0.0":
            continue
        if _RFC1918.match(ip):
            continue
        parts = ip.split(".")
        if any(int(p) > 255 for p in parts):
            continue
        return True
    return False


def apply_fp_routing(findings, evidence_db=None) -> int:
    """In-place. Set ``_fp_routing_benign`` on findings that should route benign.
    Returns the count flagged. Conservative -- never flags a finding with its own
    independent malice or an explicit malicious verdict. Entity propagation never
    clears a finding carrying its own EXTERNAL egress (see _has_external_peer)."""
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    # entities ReAct judged benign anywhere
    benign_pids: set = set()
    for f in findings:
        if _benign_verdict(f):
            benign_pids |= _entity_pids(f)

    flagged = 0
    for f in findings:
        if f.get("_fp_routing_benign"):
            continue
        if _malicious_verdict(f) or has_independent_malice(f, evidence_db):
            continue
        # (1) loopback-only + benign verdict -> honor benign over any anomaly hold
        if _benign_verdict(f) and loopback_only(f):
            f["_fp_routing_benign"] = True
            f["_fp_routing_reason"] = "loopback_benign"
            flagged += 1
            continue
        # (2) per-entity benign propagation -- vetoed when the receiving finding
        # carries its OWN external egress (distinct behavior, never adjudicated
        # by the donor verdict; could mask exfiltration from a sensitive process)
        if (benign_pids and (_entity_pids(f) & benign_pids)
                and not _benign_verdict(f) and not _has_external_peer(f)):
            f["_fp_routing_benign"] = True
            f["_fp_routing_reason"] = "entity_benign_propagation"
            flagged += 1
    return flagged


__all__ = ["apply_fp_routing", "loopback_only", "has_independent_malice"]
