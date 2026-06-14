"""Dedup-by-(entity, technique) pass (env-gated SIFT_DEDUP) -- pre-routing.

The ensemble fingerprint dedupes on ENTITY alone, but the technique lives in member
prose, so near-identical findings about the SAME artifact survive separately and get
coin-flipped into different disposition tiers (the live run showed one IFEO sethc
backdoor across three findings at three tiers, one PSEXESVC service both CONFIRMED
and UNRESOLVED). This final safety-net collapses them: group findings by
(technique-family, target-token), keep the single representative most likely to be
the true disposition (validated > has-signal > malicious-verdict > severity >
confidence > tool-breadth), and merge the dropped members' source tools into it.

Runs on findings_final BEFORE routing, so the disposition buckets and the partition
gate stay consistent (one source, deduped once).

Universal / dataset-agnostic: the technique family is read from the registered
malicious-semantic signals, else from OS-PRIMITIVE structural tokens (registry-key
shapes, Event IDs, ports, privilege names, RWX) -- never a tool / malware / case
name. The target token is EXTRACTED from the finding (registry leaf / ip:port /
service / process), never hardcoded.
"""
from __future__ import annotations

import re

from sift_sentinel.analysis.disposition import extract_react_verdict

# technique-family <- OS-primitive structural tokens (NO tool/malware names).
_TECH_PATTERNS = [
    ("ifeo_persistence", r"image file execution options|\bifeo\b"),
    ("safeboot_persistence", r"safeboot|alternateshell"),
    ("run_key_persistence", r"currentversion[\\/]+run\b|\brun key\b"),
    ("service_persistence", r"\\services\\|/services/|service.{0,20}persist|imagepath"),
    ("explicit_cred_logon", r"\b4648\b|explicit credential"),
    ("share_access", r"\b5140\b|admin share|network share"),
    ("lateral_smb", r"\bsmb\b|\bport 445\b|:445\b"),
    ("lateral_rdp", r"\brdp\b|\bport 3389\b|:3389\b"),
    ("c2_network", r"\bc2\b|command.and.control|:8080\b|exfiltrat"),
    ("memory_injection", r"page_execute_readwrite|\brwx\b|memory injection|reflective"),
    ("reflection_exec", r"reflection|getprocaddress|unsafe native"),
    ("privilege_context", r"\bse[a-z]+privilege\b|sensitive privilege|token manipulation"),
    ("temp_staging", r"\\temp\\|/temp/|staging director"),
]

_REG_LEAF = re.compile(r"[\\/]([^\\/]+[\\/][^\\/]+)$")
_IPPORT = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\s*[:]?\s*(\d{1,5})?\b")
_PROC = re.compile(r"\b([a-z0-9_.-]+\.exe)\b", re.I)


def _norm(s) -> str:
    return re.sub(r"\s+", " ", str(s or "").strip().lower())


def _text(f: dict) -> str:
    parts = [str(f.get(k) or "") for k in ("title", "description", "raw_excerpt")]
    for c in f.get("claims") or []:
        if isinstance(c, dict):
            parts.append(" ".join(str(v) for v in c.values()))
    art = f.get("primary_artifact") or f.get("artifact")
    if isinstance(art, str):
        parts.append(art)
    return " ".join(parts)


def _technique(f: dict) -> str:
    # Structural keywords FIRST: they appear in every duplicate's text (registry
    # shape / port / privilege name), so dupes derive the SAME family whether or
    # not one of them also carried the matcher signal. Signal is the fallback.
    t = _norm(_text(f))
    for name, pat in _TECH_PATTERNS:
        if re.search(pat, t):
            return name
    sigs = sorted({_norm(s) for s in (f.get("malicious_semantic_signals") or []) if s})
    return ("sig:" + sigs[0]) if sigs else ""


def _target(f: dict) -> str:
    """The most specific normalized entity token, EXTRACTED (never hardcoded)."""
    blob = _text(f)
    # registry leaf (last two path segments) -- e.g. <exe>/debugger, .../alternateshell
    m = _REG_LEAF.search(blob.replace("\\", "/"))
    if m and ("/" in m.group(1)):
        return _norm(m.group(1)).replace("\\", "/")
    # service name
    msvc = re.search(r"service[:=]?\s*([a-z0-9_.$-]+)", blob, re.I)
    if msvc:
        return "svc:" + _norm(msvc.group(1))
    # ip:port
    mip = _IPPORT.search(blob)
    if mip and mip.group(1) and not mip.group(1).startswith("0.0.0.0"):
        return "%s:%s" % (mip.group(1), mip.group(2) or "")
    # process image
    mp = _PROC.search(blob)
    if mp:
        return "proc:" + _norm(mp.group(1))
    return ""


def dedup_key(f: dict):
    """(technique, target) or None when no confident key is extractable (-> never
    merged: conservative)."""
    if not isinstance(f, dict):
        return None
    tech = _technique(f)
    tgt = _target(f)
    if not tech or not tgt:
        return None
    return (tech, tgt)


def _source_tools(f: dict) -> set:
    out = set()
    for k in ("source_tools", "tools", "tool_hits", "claim_tools"):
        v = f.get(k)
        if isinstance(v, list):
            out |= {str(x) for x in v if x}
    return out


def _malice_rank(f: dict):
    sev = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
        str(f.get("severity", "")).upper(), 0)
    conf = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
        str(f.get("confidence_level") or f.get("confidence") or "").upper(), 0)
    validated = 1 if (str(f.get("deterministic_check", "")).lower() == "passed"
                      or str(f.get("validation_status", "")).lower() in ("match", "verified")) else 0
    has_sig = 1 if (f.get("malicious_semantic_signals")) else 0
    v, _ = extract_react_verdict(f, None)
    vl = str(v or "").lower()
    vrank = 2 if vl in ("confirmed_malicious", "malicious") else (
        -1 if vl in ("confirmed_benign", "likely_fp", "benign") else 0)
    return (validated, has_sig, vrank, sev, conf, len(_source_tools(f)))


def dedupe_findings(findings):
    """Collapse (technique, target) duplicates in ``findings``. Returns
    ``(deduped_list, dropped_count)``. Keeps the highest-malice-rank representative
    and merges dropped members' source tools into it. Findings with no confident
    key pass through untouched."""
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    groups: dict = {}
    order: list = []
    passthrough: list = []
    for f in findings:
        k = dedup_key(f)
        if k is None:
            passthrough.append(f)
            continue
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(f)

    kept: list = []
    dropped = 0
    for k in order:
        members = groups[k]
        if len(members) == 1:
            kept.append(members[0])
            continue
        rep = max(members, key=_malice_rank)
        merged_tools = set(rep.get("source_tools") or [])
        for m in members:
            if m is rep:
                continue
            merged_tools |= _source_tools(m)
            dropped += 1
        if merged_tools:
            rep["source_tools"] = sorted(merged_tools)
        rep["dedup_merged_count"] = len(members) - 1
        kept.append(rep)

    # preserve original order as much as possible: keep+passthrough by first-seen
    result = [f for f in findings if (f in kept or f in passthrough)]
    return result, dropped


__all__ = ["dedup_key", "dedupe_findings"]
