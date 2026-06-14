"""XCORR: deterministic cross-artifact corroboration enrichment.

A finding frequently cites ONE source tool even when the EvidenceDB knows its
entity (a file path, hash, or service/driver name) was independently observed
by tools across several artifact domains. The corroboration exists but never
reaches the finding, so calibrate_confidence's "3+ artifact types = HIGH"
ceiling cannot fire and a real multi-domain detection stays MEDIUM.

This pass attaches that corroboration deterministically: look the finding's
own claim entities up in the EvidenceDB (index lookups + one bounded scan of
fact text fields), collect the distinct producing tools and fact families, and
ONLY when the union of artifact types reaches the floor (3+, the same bar the
calibrator uses for HIGH) attach the corroborating tools to source_tools.
Below the floor the finding is left byte-identical -- enrichment that lands at
2 types would otherwise trigger the pre-existing 2-domain HIGH upgrade, which
is weaker corroboration than this pass is willing to vouch for.

Universal / dataset-agnostic: entities come from the finding's structured
claims; the corroboration map is built per-run from the case's own EvidenceDB.
No name vocabulary, no thresholds tuned to a sample. Truthful by construction:
a tool is attached only when one of its compiled facts actually references the
entity (and, mirroring the calibrator's B5 phantom filter, only when the tool
measurably produced records). Kill-switch: SIFT_XCORR=0.
"""
from __future__ import annotations

import os
import re
from typing import Any

from .confidence import TOOL_TO_ARTIFACT_TYPE
from .evidence_db import normalize_path

# Fact bookkeeping keys that never carry entity-bearing text.
_SKIP_FACT_KEYS = {
    "fact_id", "fact_type", "fact_signature", "confidence_hint",
    "source_tool", "source_tools", "source_record_index",
    "source_record_indices", "record_ref", "record_refs", "merge_count",
}

# A basename is only regex-scanned when it is specific enough that a match in
# another domain's fact text is real corroboration, not a token collision:
# at least 5 chars and carrying an extension ("x.sys" is the minimum shape).
_MIN_BASENAME_LEN = 5

_HASH_RE = re.compile(r"^[a-f0-9]{32}(?:[a-f0-9]{8})?(?:[a-f0-9]{24})?$")


def _basename(norm_path: str) -> str:
    return norm_path.rsplit("/", 1)[-1] if norm_path else ""


def _scannable_basename(name: str) -> bool:
    return bool(name) and len(name) >= _MIN_BASENAME_LEN and "." in name


def _finding_entities(finding: dict) -> dict[str, set]:
    """Extract the finding's own structured entities: normalized full paths,
    scannable basenames, lowercase hashes, lowercase service names."""
    paths: set[str] = set()
    hashes: set[str] = set()
    services: set[str] = set()
    for c in finding.get("claims") or []:
        if not isinstance(c, dict):
            continue
        for pk in ("normalized_path", "path", "file_path", "file", "value"):
            v = c.get(pk)
            if isinstance(v, str) and ("\\" in v or "/" in v):
                np = normalize_path(v)
                if np:
                    paths.add(np)
        for hk in ("sha1", "sha256", "md5", "hash"):
            v = c.get(hk)
            if isinstance(v, str) and _HASH_RE.match(v.strip().lower()):
                hashes.add(v.strip().lower())
        v = c.get("service_name")
        if isinstance(v, str) and v.strip():
            services.add(v.strip().lower())
    basenames = {b for b in (_basename(p) for p in paths)
                 if _scannable_basename(b)}
    # a driver/service registered under its file stem is universal Windows
    # structure (services/<stem> -> <stem>.sys); look the stem up as a service
    services |= {b.rsplit(".", 1)[0] for b in basenames}
    return {"paths": paths, "basenames": basenames,
            "hashes": hashes, "services": services}


def _fact_text_values(fact: dict) -> list[str]:
    out: list[str] = []
    for k, v in fact.items():
        if k in _SKIP_FACT_KEYS:
            continue
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            out.extend(x for x in v if isinstance(x, str))
    return out


def _family_of(fact_id: str) -> str:
    return str(fact_id).rsplit("-", 1)[0]


def enrich_findings_with_xcorr(
    findings: list[dict],
    evdb: dict | None,
    *,
    min_types: int = 3,
    tool_records: dict[str, int] | None = None,
) -> list[dict]:
    """Attach EvidenceDB-corroborated source_tools to each finding whose
    entity spans >= min_types artifact types. Mutates in place + returns."""
    if os.environ.get("SIFT_XCORR", "1") == "0":
        return findings
    typed = (evdb or {}).get("typed_facts") or {}
    indexes = (evdb or {}).get("indexes") or {}
    if not typed or not findings:
        return findings

    per_finding = [(f, _finding_entities(f)) for f in findings
                   if isinstance(f, dict)]
    all_basenames = sorted({b for _, e in per_finding for b in e["basenames"]})
    if not (all_basenames
            or any(e["hashes"] or e["services"] or e["paths"]
                   for _, e in per_finding)):
        return findings

    id2fact: dict[str, dict] = {}
    for facts in typed.values():
        for fact in facts or []:
            if isinstance(fact, dict) and fact.get("fact_id"):
                id2fact[str(fact["fact_id"])] = fact

    def _tools_of(fact: dict) -> list[str]:
        tools = fact.get("source_tools") or []
        if not tools and fact.get("source_tool"):
            tools = [fact["source_tool"]]
        return [t for t in tools if isinstance(t, str) and t]

    # hits: entity token -> set of (family, tool)
    hits: dict[str, set] = {}

    def _record(token: str, fact: dict) -> None:
        fam = str(fact.get("fact_type") or _family_of(fact.get("fact_id", "")))
        bucket = hits.setdefault(token, set())
        for tool in _tools_of(fact):
            bucket.add((fam, tool))

    # 1) exact index lookups (full normalized path / hash / service name)
    for idx_name, key in (("by_path", "paths"), ("by_hash", "hashes"),
                          ("by_service_name", "services")):
        bucket = indexes.get(idx_name) or {}
        wanted = {t for _, e in per_finding for t in e[key]}
        for token in wanted & set(bucket.keys()):
            for fid in bucket.get(token) or []:
                fact = id2fact.get(str(fid))
                if fact:
                    _record(token, fact)

    # 2) one bounded pass over fact text for basename mentions -- catches
    # families with no path index (event details, registry value data,
    # \\Device\\-prefixed handle names) without per-finding rescans.
    if all_basenames:
        alternation = re.compile(
            r"(?:^|[^a-z0-9_.-])(%s)(?:[^a-z0-9_.-]|$)"
            % "|".join(re.escape(b) for b in all_basenames))
        for facts in typed.values():
            for fact in facts or []:
                if not isinstance(fact, dict):
                    continue
                for text in _fact_text_values(fact):
                    for m in alternation.finditer(text.lower()):
                        _record(m.group(1), fact)

    enriched = 0
    for finding, ents in per_finding:
        pairs: set = set()
        for token in (ents["paths"] | ents["basenames"]
                      | ents["hashes"] | ents["services"]):
            pairs |= hits.get(token, set())
        if not pairs:
            continue
        discovered = {tool for _, tool in pairs}
        if tool_records is not None:
            discovered = {t for t in discovered
                          if tool_records.get(t, 0) > 0}
        existing = [t for t in (finding.get("source_tools") or [])
                    if isinstance(t, str)]
        new_tools = sorted(discovered - set(existing))
        if not new_tools:
            continue
        union_types = {TOOL_TO_ARTIFACT_TYPE.get(t)
                       for t in (set(existing) | discovered)}
        union_types.discard(None)
        if len(union_types) < min_types:
            continue        # below the floor: leave the finding untouched
        finding["source_tools"] = existing + new_tools
        families = sorted({fam for fam, tool in pairs if tool in discovered})
        finding["xcorr_corroboration"] = {
            "families": families,
            "tools": sorted(discovered),
            "artifact_types": sorted(union_types),
        }
        enriched += 1
    return findings
