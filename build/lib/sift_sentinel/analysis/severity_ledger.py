"""Severity ledger + post-Step-13 drift guard (slot 31C2-FIX-A).

Why this module exists
----------------------
A live run showed self-corrected single-tool network/listener
findings that were calibrated LOW at Step 13 but rendered CRITICAL
on the final console, and descriptions that called a private
RFC1918 address "external IP <addr>".

That is a C2/C5 audit-trail bug: a self-corrected single-tool
network/listener fact must not silently become CRITICAL in the
final display, and a private/internal address must not be called
"external" in human-readable text.

This module is the deterministic gate that catches that drift:

  * ``record_after_step13(findings)`` -- snapshot per-finding
    severity / confidence_level / source_tools / claim_tools /
    self_corrected immediately after Step 13 calibrate.

  * ``cap_self_corrected_single_tool(finding)`` -- when a finding is
    ``self_corrected`` and its (deduped) source_tools is exactly one
    tool from the restricted network/listener/service set
    (``RESTRICTED_SINGLE_TOOLS``, which includes ``vol_netscan``),
    cap display severity at LOW (MEDIUM only when a confirmed malicious
    semantic signal explicitly supports it) and tag the finding for
    route-out from ``confirmed_malicious_atomic``.

  * ``normalize_private_ip_wording(text)`` -- rewrite
    "external IP <addr>" / "external address <addr>" to
    "private/internal address <addr>" when ``ipaddress`` classifies
    <addr> as private / loopback / link-local / reserved. The
    classifier is the standard library, with no hardcoded networks.

  * ``apply_post_step13_normalization(findings)`` -- single entry
    point for the coordinator. Records ledger, runs cap + wording
    normalization in place across every human-readable field, and
    returns an audit dict.

  * ``verify_no_drift(prev_ledger, findings, allowed_reasons)`` --
    final gate before the report / final console: any upward
    severity move from the snapshot without a recorded
    ``allowed_reason`` is a violation. Empty list == PASS.

Pure deterministic Python, dataset-agnostic. No hardcoded
CIDR/network table; the IP classifier delegates to the stdlib
``ipaddress`` flags. No case-specific PIDs, IPs, users, paths,
domains, or process names anywhere in this module.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Iterable

logger = logging.getLogger(__name__)

# Severity rank used for drift comparison. Higher = more severe.
_SEVERITY_RANK: dict[str, int] = {
    "UNRESOLVED": -1,
    "SPECULATIVE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Tools whose facts must not silently become CRITICAL when the finding
# was self-corrected and only this single tool supports it. These are
# the real runtime registry tool names; this set is intentionally
# generic (no case-specific tools, no fake tools).
_NETWORK_LISTENER_TOOLS: frozenset[str] = frozenset({
    "vol_netscan",
})
_SERVICE_TOOLS: frozenset[str] = frozenset({
    "vol_svcscan",
})
RESTRICTED_SINGLE_TOOLS: frozenset[str] = (
    _NETWORK_LISTENER_TOOLS | _SERVICE_TOOLS
)

# Cap target when no malicious_semantic_signals strongly support the
# self-corrected single-tool finding. MEDIUM ceiling when there *is*
# semantic support but the finding is still single-tool self-corrected.
_DEFAULT_CAP = "LOW"
_SEMANTIC_SUPPORTED_CAP = "MEDIUM"

# Audit reason strings used by callers + drift verifier.
REASON_SELF_CORRECTED_SINGLE_TOOL = "self_corrected_single_tool_cap"

# Wildcard / unspecified address tokens that must not classify as
# internal even though ``ipaddress`` may parse them.
_WILDCARD_ADDRS: frozenset[str] = frozenset({"*", "0.0.0.0", "::"})

# IPv4 literal anywhere in a piece of text. Conservative on bounds
# (no leading-zero handling) so it does not steal e.g. a "1.2.3.4.5"
# version string -- the surrounding regex enforces word-class
# boundaries on either side.
_IPV4_RE = re.compile(
    r"(?<![\w.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\w.])"
)

# Rewrite patterns for "external IP <addr>" / "external address <addr>"
# wording. Case-insensitive, tolerant of an optional intervening word.
_EXTERNAL_IP_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\bexternal\s+IP(?:\s+address)?\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bexternal\s+address\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bexternal\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        re.IGNORECASE,
    ),
)


def is_private_or_internal(addr: str) -> bool:
    """Dataset-agnostic private/internal address classifier.

    Delegates entirely to ``ipaddress`` flags -- no hardcoded
    CIDR/network table. Returns False on parse failure, empty input,
    or a wildcard / unspecified token (``*``, ``0.0.0.0``, ``::``).
    """
    text = (addr or "").strip()
    if not text or text in _WILDCARD_ADDRS:
        return False
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
    )


def extract_ipv4(text: str) -> list[str]:
    """Return all unique IPv4 literals appearing in ``text``."""
    if not isinstance(text, str) or not text:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for m in _IPV4_RE.finditer(text):
        v = m.group(1)
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def normalize_private_ip_wording(text: str) -> tuple[str, list[str]]:
    """Rewrite "external IP <addr>" -> "private/internal address <addr>".

    Always returns a ``(rewritten_text, addresses_rewritten)`` tuple.
    ``addresses_rewritten`` is in first-seen order and deduped. Only
    rewrites when ``is_private_or_internal(addr)`` is True; public
    addresses are left untouched and never appear in the second
    return value.
    """
    if not isinstance(text, str) or not text:
        return text if isinstance(text, str) else "", []
    rewritten: list[str] = []
    rewritten_seen: set[str] = set()

    def _sub(match: re.Match[str]) -> str:
        addr = match.group(1)
        if is_private_or_internal(addr):
            if addr not in rewritten_seen:
                rewritten.append(addr)
                rewritten_seen.add(addr)
            return f"private/internal address {addr}"
        return match.group(0)

    new = text
    for pat in _EXTERNAL_IP_PATTERNS:
        new = pat.sub(_sub, new)
    return new, rewritten


@dataclass
class SeverityRecord:
    """Per-finding snapshot used for drift checks + audit."""

    finding_id: str
    severity: str
    confidence_level: str
    source_tools: list[str] = field(default_factory=list)
    claim_tools: list[str] = field(default_factory=list)
    self_corrected: bool = False
    allowed_reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "confidence_level": self.confidence_level,
            "source_tools": list(self.source_tools),
            "claim_tools": list(self.claim_tools),
            "self_corrected": bool(self.self_corrected),
            "allowed_reasons": list(self.allowed_reasons),
        }


def _norm_severity(value) -> str:
    s = str(value or "").strip().upper()
    if s in _SEVERITY_RANK:
        return s
    return "LOW"


def _norm_confidence(value) -> str:
    s = str(value or "").strip().upper()
    return s if s else "LOW"


def _dedup(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for v in values or ():
        if not isinstance(v, str) or not v:
            continue
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def record_after_step13(findings: Iterable[dict]) -> dict[str, SeverityRecord]:
    """Snapshot the Step-13 severity / confidence / provenance ledger."""
    ledger: dict[str, SeverityRecord] = {}
    for f in findings or ():
        if not isinstance(f, dict):
            continue
        fid = str(f.get("finding_id") or "").strip()
        if not fid:
            continue
        ledger[fid] = SeverityRecord(
            finding_id=fid,
            severity=_norm_severity(f.get("severity")),
            confidence_level=_norm_confidence(f.get("confidence_level")),
            source_tools=_dedup(f.get("source_tools") or []),
            claim_tools=_dedup(f.get("claim_tools") or []),
            self_corrected=bool(f.get("self_corrected")),
        )
    return ledger


def _has_strong_semantic_support(finding: dict) -> bool:
    """True iff the finding declares at least one confirmed malicious signal.

    Uses the registry check that ``disposition.py`` already trusts;
    only registered signal names count as support. Free-text
    descriptions cannot inject support.
    """
    try:
        from sift_sentinel.analysis.malicious_semantics import (
            has_malicious_semantic,
        )
    except Exception:  # pragma: no cover - import-time safety only
        return False
    try:
        has, _ = has_malicious_semantic(finding, None)
    except Exception:
        return False
    return bool(has)


def _is_self_corrected_single_restricted_tool(
    finding: dict,
) -> tuple[bool, str | None]:
    """True if (self_corrected) AND (exactly 1 unique source tool) AND
    (that tool is in RESTRICTED_SINGLE_TOOLS).

    Returns ``(matches, tool_name_or_None)``.
    """
    if not isinstance(finding, dict):
        return False, None
    if not bool(finding.get("self_corrected")):
        return False, None
    tools = _dedup(finding.get("source_tools") or [])
    if len(tools) != 1:
        return False, None
    tool = tools[0]
    if tool not in RESTRICTED_SINGLE_TOOLS:
        return False, None
    return True, tool


def cap_self_corrected_single_tool(finding: dict) -> dict | None:
    """Cap a self-corrected single-tool restricted-tool finding's
    display severity. Returns an audit dict (or ``None`` if no cap).

    Mutates ``finding`` in place. When the cap applies, the finding
    carries three explicit flags so downstream disposition / display
    code does not have to re-derive intent:

      finding["severity_ledger_cap_applied"]      = True
      finding["severity_ledger_route_out"]        = True (unless
          a confirmed malicious_semantic_signal supports the finding)
      finding["severity_ledger_route_out_reason"] = generic reason
    """
    matches, tool = _is_self_corrected_single_restricted_tool(finding)
    if not matches or tool is None:
        return None

    before = _norm_severity(finding.get("severity"))
    has_sem = _has_strong_semantic_support(finding)
    target = _SEMANTIC_SUPPORTED_CAP if has_sem else _DEFAULT_CAP

    capped = _SEVERITY_RANK[before] > _SEVERITY_RANK[target]
    if capped:
        finding["severity"] = target
        finding["severity_cap_origin"] = before
        finding["severity_cap_reason"] = (
            f"{REASON_SELF_CORRECTED_SINGLE_TOOL}:{tool}"
        )

    # Always set the cap-applied flag on a matching finding (even when
    # severity was already at-or-below cap), so downstream readers can
    # see that the ledger inspected it.
    finding["severity_ledger_cap_applied"] = True

    if not has_sem:
        finding["severity_ledger_route_out"] = True
        finding["severity_ledger_route_out_reason"] = (
            f"{REASON_SELF_CORRECTED_SINGLE_TOOL}:{tool}"
        )

    if capped:
        logger.info(
            "  %s: severity capped %s -> %s (self-corrected single-tool=%s, "
            "semantic_support=%s)",
            finding.get("finding_id", "?"),
            before, target, tool, has_sem,
        )
        return {
            "finding_id": str(finding.get("finding_id") or ""),
            "tool": tool,
            "severity_before": before,
            "severity_after": target,
            "semantic_support": has_sem,
            "reason": REASON_SELF_CORRECTED_SINGLE_TOOL,
        }
    # Already at-or-below cap: no severity change, but cap-applied
    # + route-out flags above still recorded.
    return None


_WORDING_FIELDS: tuple[str, ...] = (
    "title",
    "artifact",
    "description",
    "summary",
    "narrative",
    "details",
    "alternative_explanations",
)


def _normalize_wording_on_finding(finding: dict) -> list[str]:
    """Rewrite private-IP wording across every human-readable field.

    Absent or non-string fields are skipped safely. Returns the
    deduped first-seen-order list of addresses that were rewritten
    anywhere on the finding.
    """
    rewritten_all: list[str] = []
    if not isinstance(finding, dict):
        return rewritten_all
    for key in _WORDING_FIELDS:
        val = finding.get(key)
        if not isinstance(val, str) or not val:
            continue
        new, rewritten = normalize_private_ip_wording(val)
        if rewritten:
            finding[key] = new
            rewritten_all.extend(rewritten)
    return _dedup(rewritten_all)


def apply_post_step13_normalization(findings: list[dict]) -> dict:
    """Run cap + wording normalization in place. Single entry point.

    Returns an audit dict::

        {
          "ledger_pre":       {fid: {...}, ...},
          "ledger_post":      {fid: {...}, ...},
          "caps":             [audit dict, ...],
          "wording_rewrites": [{"finding_id": fid, "addrs": [...]}, ...],
        }

    Idempotent: calling twice produces no additional caps (because
    severity is already at the cap target on the second pass) and no
    additional wording rewrites (because the "external" wording has
    already been replaced).
    """
    ledger_pre = {
        fid: r.as_dict() for fid, r in record_after_step13(findings).items()
    }
    caps: list[dict] = []
    wording_rewrites: list[dict] = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        rewritten = _normalize_wording_on_finding(f)
        if rewritten:
            wording_rewrites.append({
                "finding_id": str(f.get("finding_id") or ""),
                "addrs": rewritten,
            })
        cap_audit = cap_self_corrected_single_tool(f)
        if cap_audit:
            caps.append(cap_audit)
    ledger_post = {
        fid: r.as_dict() for fid, r in record_after_step13(findings).items()
    }
    return {
        "ledger_pre": ledger_pre,
        "ledger_post": ledger_post,
        "caps": caps,
        "wording_rewrites": wording_rewrites,
    }


def verify_no_drift(
    prev_ledger: dict[str, SeverityRecord] | dict[str, dict],
    findings: Iterable[dict],
    allowed_reasons: dict[str, list[str]] | None = None,
) -> list[dict]:
    """Return drift violations. Empty list == PASS.

    A drift violation is recorded when a finding's current severity
    rank is **strictly greater** than its snapshot severity rank, AND
    no matching ``allowed_reasons[fid]`` was registered for it.
    Downward moves are always allowed without a reason.
    """
    allowed_reasons = allowed_reasons or {}
    out: list[dict] = []
    for f in findings or ():
        if not isinstance(f, dict):
            continue
        fid = str(f.get("finding_id") or "").strip()
        if not fid:
            continue
        prev = prev_ledger.get(fid) if prev_ledger else None
        if prev is None:
            continue
        if isinstance(prev, SeverityRecord):
            prev_sev = prev.severity
        else:
            prev_sev = _norm_severity(prev.get("severity"))
        cur_sev = _norm_severity(f.get("severity"))
        if _SEVERITY_RANK.get(cur_sev, 1) <= _SEVERITY_RANK.get(prev_sev, 1):
            continue
        reasons = list(allowed_reasons.get(fid) or [])
        if reasons:
            continue
        out.append({
            "finding_id": fid,
            "severity_before": prev_sev,
            "severity_after": cur_sev,
            "source_tools": list(f.get("source_tools") or []),
            "self_corrected": bool(f.get("self_corrected")),
        })
    return out
