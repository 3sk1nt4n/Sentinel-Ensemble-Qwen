"""LLM semantic dedup -- the LAST pass, after inv3a + deterministic dedup.

The deterministic dedup collapses dupes that share a structural key (hash, path,
registry-fact, pid, event, domain). What it can't catch is the SAME finding worded
differently across ensemble members (one registry-persistence value emitted under
four slightly different titles, two phrasings of one reflective-loader behavior, two
attack-chain summaries). The LLM is good at that semantic grouping.

Design: the LLM only PROPOSES duplicate groups; a DETERMINISTIC guard verifies each
group before any merge, so an over-merge (the LLM lumping two distinct findings) is
rejected, not applied. Universal-safe by construction:
  * merges only WITHIN one table (TP rows together, FP rows together) -- a TP can
    never be merged into an FP, so no evil is hidden by dedup.
  * a proposed group is applied ONLY if its members share a real signal -- an
    entity_keys intersection OR >=2 significant shared title tokens. The LLM cannot
    merge "p.exe staging" with "RDP lateral movement" (zero shared signal -> rejected).
  * canonical = the strongest row (most tool hits, then most claims); dupes are
    DROPPED but their ids are attached to the canonical (_merged_duplicate_ids), so
    no information is lost.
Kill-switch SIFT_LLM_DEDUP. The LLM call is injected (adjudicator_fn) so the whole
pass is unit-testable with no network.
"""
from __future__ import annotations

import json
import os
import re

CONFIRMED = "confirmed_malicious_atomic"
REVIEW = "suspicious_needs_review"
BENIGN = "benign_or_false_positive"
INCONCLUSIVE = "inconclusive_unresolved"

# the two tables the user sees; merges never cross between them
_TP_BUCKETS = (CONFIRMED, REVIEW)
_FP_BUCKETS = (BENIGN, INCONCLUSIVE)

_STOP = frozenset({
    "the", "a", "an", "of", "to", "in", "on", "and", "or", "via", "with", "from",
    "for", "by", "is", "are", "was", "were", "process", "finding", "execution",
    "suspicious", "possible", "detected", "evidence", "activity", "ta0001", "ta0002",
    "ta0003", "ta0004", "ta0005", "ta0006", "ta0008", "ta0009", "ta0011",
})
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9.\-]{2,}")


def enabled() -> bool:
    return os.environ.get("SIFT_LLM_DEDUP", "").strip().lower() in (
        "1", "true", "yes", "on")


def _fid(f) -> str:
    return str((f or {}).get("finding_id") or (f or {}).get("id") or "")


def _title_tokens(f) -> set:
    t = " ".join(str(f.get(k) or "") for k in ("title", "artifact", "primary_artifact")).lower()
    return {w for w in _TOKEN_RE.findall(t) if w not in _STOP}


def _tool_count(f) -> int:
    t = f.get("source_tools") or f.get("tools") or f.get("tool_hits") or []
    return len(t) if isinstance(t, (list, tuple, set)) else (1 if t else 0)


def _claim_count(f) -> int:
    c = f.get("claims") or []
    return len(c) if isinstance(c, list) else 0


_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_PIDV_RE = re.compile(r"\bpid[:=]?\s*(\d{2,7})\b", re.I)


def _entity_text(f) -> str:
    parts = [str(f.get(k) or "") for k in ("title", "description", "artifact", "primary_artifact")]
    for c in (f.get("claims") or []):
        if isinstance(c, dict):
            parts += [str(v) for v in c.values()]
    return " ".join(parts)


def _conflicting_entities(a, b) -> bool:
    """True when a and b reference the SAME entity TYPE but DIFFERENT values -- two
    different IPs, or two different PIDs. Templated findings ('lateral movement admin
    share: ip:X') share generic title tokens, so the token check alone would wrongly
    merge two distinct targets; this rejects that, so a real lateral-movement target
    or a distinct injected process is never lost to dedup."""
    ia = {m.group(0) for m in _IPV4_RE.finditer(_entity_text(a))}
    ib = {m.group(0) for m in _IPV4_RE.finditer(_entity_text(b))}
    if ia and ib and not (ia & ib):           # both name IPs, disjoint -> different targets
        return True
    try:
        from sift_sentinel.analysis.fp_routing import _entity_pids
        pa, pb = _entity_pids(a), _entity_pids(b)   # reads claim.pid + 'PID n' in text
        if pa and pb and not (pa & pb):       # both name PIDs, disjoint -> different processes
            return True
    except Exception:
        pass
    return False


def _shares_signal(a, b) -> bool:
    """Deterministic over-merge guard: two findings may merge only if they share a
    real entity key OR >=2 significant title tokens, AND they do NOT reference
    conflicting distinct entities (different IPs / PIDs)."""
    if _conflicting_entities(a, b):
        return False                          # different target/process -> never merge
    try:
        from sift_sentinel.analysis.confirmed_dedup import entity_keys
        if entity_keys(a) & entity_keys(b):
            return True
    except Exception:
        pass
    return len(_title_tokens(a) & _title_tokens(b)) >= 2


def build_dedup_prompt(findings: list) -> str:
    lines = [
        "You are de-duplicating a forensic findings table. Below are findings that",
        "are ALL in the same table. Group together the ones that describe the SAME",
        "underlying thing (same process/entity, same behavior, same evidence) even if",
        "worded differently. Do NOT group findings that are merely related or part of",
        "the same attack -- only TRUE duplicates of one another.",
        "",
        'Return ONLY JSON: {"groups": [["<keep_id>", "<dup_id>", ...], ...]}',
        "Each inner list is one duplicate set; the FIRST id is the one to keep.",
        "Omit findings that have no duplicate. Keep it strict.",
        "",
        "Findings:",
    ]
    for f in findings:
        desc = str(f.get("title") or f.get("description") or f.get("artifact") or "")
        desc = desc.replace("\n", " ").strip()[:160]
        lines.append('- id=%s | "%s"' % (_fid(f), desc))
    return "\n".join(lines)


def parse_dedup_groups(text: str) -> list:
    """Tolerant parse -> list of id-lists. Accepts {"groups":[[...]]} or a bare [[...]]."""
    if not text:
        return []
    data = None
    for cand in (text, text[text.find("{"):text.rfind("}") + 1],
                 text[text.find("["):text.rfind("]") + 1]):
        try:
            data = json.loads(cand)
            break
        except Exception:
            continue
    if isinstance(data, dict):
        data = data.get("groups") or data.get("duplicates") or []
    if not isinstance(data, list):
        return []
    out = []
    for g in data:
        if isinstance(g, list) and len(g) >= 2:
            ids = [str(x).strip() for x in g if str(x).strip()]
            if len(ids) >= 2:
                out.append(ids)
    return out


def _dedup_one_table(buckets, table_keys, adjudicator_fn, ledger):
    by_id = {}
    bucket_of = {}
    for bk in table_keys:
        for f in (buckets.get(bk) or []):
            if isinstance(f, dict) and _fid(f):
                by_id[_fid(f)] = f
                bucket_of[_fid(f)] = bk
    if len(by_id) < 2:
        return
    prompt = build_dedup_prompt(list(by_id.values()))
    try:
        groups = parse_dedup_groups(adjudicator_fn(prompt) or "")
    except Exception:
        return
    removed = set()
    for g in groups:
        members = [by_id[i] for i in g if i in by_id and i not in removed]
        if len(members) < 2:
            continue
        # GUARD: every dup must share a real signal with the canonical -> reject over-merge
        canon = max(members, key=lambda f: (_tool_count(f), _claim_count(f)))
        dups = [m for m in members if _fid(m) != _fid(canon)
                and _shares_signal(canon, m)]
        if not dups:
            continue
        canon.setdefault("_merged_duplicate_ids", [])
        for d in dups:
            did = _fid(d)
            canon["_merged_duplicate_ids"].append(did)
            removed.add(did)
            ledger.append({"kept": _fid(canon), "dropped": did,
                           "table": "TP" if table_keys == _TP_BUCKETS else "FP"})
    if removed:
        for bk in table_keys:
            buckets[bk] = [f for f in (buckets.get(bk) or [])
                           if not (isinstance(f, dict) and _fid(f) in removed)]


def apply_llm_dedup(buckets, adjudicator_fn, evidence_db=None):
    """In-place-safe: returns (buckets, ledger). LLM proposes duplicate groups per
    table; a deterministic guard verifies each before merging. Merges never cross the
    TP/FP boundary; canonical keeps the dupes' ids. Recall-safe: a merge only drops a
    row that is a verified duplicate of a kept row in the SAME table."""
    if not isinstance(buckets, dict) or not callable(adjudicator_fn):
        return buckets, []
    out = {k: (list(v) if isinstance(v, list) else v) for k, v in buckets.items()}
    ledger: list = []
    try:
        _dedup_one_table(out, _TP_BUCKETS, adjudicator_fn, ledger)
        _dedup_one_table(out, _FP_BUCKETS, adjudicator_fn, ledger)
    except Exception:
        return buckets, []          # any failure => untouched
    return out, ledger


__all__ = ["apply_llm_dedup", "enabled", "build_dedup_prompt", "parse_dedup_groups"]
