from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# SIFT_ZERO_INFERENCE_EVIDENCE_CONTRACT_V1
#
# Universal policy:
# - confirmed/actionable findings must be exact evidence observations.
# - inference, guess, assumption, or speculative language cannot be promoted.
# - every promoted finding must cite at least one real data-producing forensic tool.
# - zero/non-hit/internal validation references cannot serve as proof.
# - repair is downgrade-only: unsafe promoted rows move to inconclusive.

BAD_STATUSES = {
    "error",
    "failed",
    "failure",
    "timeout",
    "not_applicable",
    "unavailable",
    "not_available",
    "unsupported",
    "skipped",
    "missing",
    "ok_no_records",
    "no_records",
}

PROMOTED_BUCKETS = {
    "confirmed_malicious_atomic",
    "suspicious_needs_review",
}

CONFIRMED_BUCKETS = {
    "confirmed_malicious_atomic",
}

INCONCLUSIVE_BUCKET = "inconclusive_unresolved"

FINDING_BUCKET_FILE = "finding_disposition_buckets.json"
AUDIT_FILE = "zero_inference_contract_audit.json"

TOOL_FIELDS = {
    "source_tool",
    "source_tools",
    "claim_tool",
    "claim_tools",
    "tools_hit",
    "tool",
    "tool_name",
    "producer_tool",
    "producer_tools",
}

TEXT_FIELDS = {
    "title",
    "name",
    "summary",
    "description",
    "details",
    "analysis",
    "finding",
    "evidence",
    "reason",
    "reasoning",
    "conclusion",
    "recommendation",
    "impact",
}

NON_FORENSIC_PROVENANCE = {
    "typed_evidence_db",
    "typed_validator",
    "reference_set",
    "check_ancestry",
    "self_correction",
    "react_cross_check",
    "provenance_taxonomy",
    "tool_hit_integrity",
    "zero_inference_contract",
}

INFERENCE_PATTERNS = [
    r"\bguess(?:ed|es|ing)?\b",
    r"\bassum(?:e|ed|es|ing|ption|ptions)\b",
    r"\bprobably\b",
    r"\bpossibly\b",
    r"\bperhaps\b",
    r"\bappears?\b",
    r"\bseems?\b",
    r"\bsuggests?\b",
    r"\bmay\s+(?:be|have|indicate|represent|show|suggest)\b",
    r"\bmight\s+(?:be|have|indicate|represent|show|suggest)\b",
    r"\bcould\s+(?:be|have|indicate|represent|show|suggest)\b",
    r"\blikely\s+(?:be|indicate|represent|show|suggest|malicious|benign)\b",
    r"\binfer(?:red|ence|ences|ring)?\b",
    r"\bnot\s+conclusive\b",
    r"\bnot\s+definitive\b",
]

INFERENCE_RE = re.compile("|".join(f"(?:{p})" for p in INFERENCE_PATTERNS), re.I)


def _load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(errors="ignore"))
    except Exception:
        return default


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True))


def canonical_tool(raw: Any) -> str:
    s = str(raw or "").strip()
    if not s:
        return ""
    if s.startswith("tool_"):
        s = s[5:]

    aliases = {
        "parse_appcompatcacheparser": "run_appcompatcacheparser",
        "tool_parse_appcompatcacheparser": "run_appcompatcacheparser",
        "vol_svescan": "vol_svcscan",
        "tool_vol_svescan": "vol_svcscan",
    }
    return aliases.get(s, s)


def _record_count(obj: Any) -> int:
    if isinstance(obj, list):
        return len(obj)
    if not isinstance(obj, dict):
        return 0

    for key in ("record_count", "records_count", "count", "total"):
        val = obj.get(key)
        if isinstance(val, int):
            return max(0, val)

    for key in ("records", "data", "items", "results", "rows", "entries"):
        val = obj.get(key)
        if isinstance(val, list):
            return len(val)

    return 0


def _status(obj: Any) -> str:
    if isinstance(obj, dict):
        for key in ("status", "result_status", "tool_status"):
            val = obj.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip().lower()
    return "ok" if _record_count(obj) > 0 else "no_records"


def build_tool_manifest(state_dir: str | Path) -> dict[str, Any]:
    state = Path(state_dir)
    all_outputs = _load_json(state / "all_outputs.json", {})
    tools: dict[str, dict[str, Any]] = {}

    if isinstance(all_outputs, dict):
        for raw_name, obj in all_outputs.items():
            name = canonical_tool(raw_name)
            if name:
                tools[name] = {
                    "records": _record_count(obj),
                    "status": _status(obj),
                }

    tool_outputs = state / "tool_outputs"
    if tool_outputs.is_dir():
        for path in tool_outputs.glob("*.json"):
            name = canonical_tool(path.stem)
            obj = _load_json(path, {})
            recs = _record_count(obj)
            stat = _status(obj)
            prev = tools.get(name)
            if prev is None or recs > int(prev.get("records") or 0):
                tools[name] = {"records": recs, "status": stat}

    producers = set()
    nonproducers = set()

    for name, meta in tools.items():
        recs = int(meta.get("records") or 0)
        stat = str(meta.get("status") or "").lower()
        if recs > 0 and stat not in BAD_STATUSES:
            producers.add(name)
        else:
            nonproducers.add(name)

    nonproducers -= producers

    return {
        "tools": tools,
        "producer_tools": sorted(producers),
        "nonproducer_tools": sorted(nonproducers),
    }


def _finding_id(finding: dict[str, Any], fallback: str) -> str:
    for key in ("id", "finding_id", "uid", "uuid"):
        val = finding.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return fallback


def _collect_tool_refs(value: Any) -> set[str]:
    refs: set[str] = set()

    if isinstance(value, dict):
        for key, val in value.items():
            if key in TOOL_FIELDS:
                if isinstance(val, list):
                    refs.update(canonical_tool(x) for x in val if str(x or "").strip())
                elif str(val or "").strip():
                    refs.add(canonical_tool(val))
            refs.update(_collect_tool_refs(val))

    elif isinstance(value, list):
        for item in value:
            refs.update(_collect_tool_refs(item))

    return {x for x in refs if x}


def _collect_human_text(value: Any, key_hint: str = "") -> list[str]:
    out: list[str] = []

    if isinstance(value, dict):
        for key, val in value.items():
            if key in TEXT_FIELDS and isinstance(val, str):
                out.append(val)
            else:
                out.extend(_collect_human_text(val, key))
    elif isinstance(value, list):
        for item in value:
            out.extend(_collect_human_text(item, key_hint))

    return out


def _has_inference_language(finding: dict[str, Any]) -> list[str]:
    hits: list[str] = []
    for text in _collect_human_text(finding):
        match = INFERENCE_RE.search(text or "")
        if match:
            hits.append(match.group(0))
    return hits


def _claims_have_source_or_refs(finding: dict[str, Any], producer_tools: set[str]) -> bool:
    claims = finding.get("claims")
    if not isinstance(claims, list) or not claims:
        return bool(_collect_tool_refs(finding) & producer_tools)

    for claim in claims:
        if not isinstance(claim, dict):
            continue

        source = canonical_tool(claim.get("source_tool") or claim.get("tool") or claim.get("claim_tool"))
        if source in producer_tools:
            return True

        for ref_key in ("evidence_refs", "evidence_ref", "typed_fact_refs", "fact_refs", "artifact_refs"):
            val = claim.get(ref_key)
            if val:
                return True

    return bool(_collect_tool_refs(finding) & producer_tools)


def classify_violation(bucket: str, finding: dict[str, Any], producer_tools: set[str]) -> list[str]:
    reasons: list[str] = []

    if bucket not in PROMOTED_BUCKETS:
        return reasons

    fid_tools = _collect_tool_refs(finding)
    producer_refs = fid_tools & producer_tools
    non_tool_refs = fid_tools & NON_FORENSIC_PROVENANCE
    inference_hits = _has_inference_language(finding)

    if not producer_refs:
        reasons.append("no_data_producing_forensic_tool")

    if non_tool_refs:
        reasons.append("internal_validation_reference_used_as_provenance")

    if not _claims_have_source_or_refs(finding, producer_tools):
        reasons.append("no_claim_level_evidence_anchor")

    if inference_hits and not _claims_have_source_or_refs(finding, producer_tools):
        reasons.append("inference_language_in_promoted_finding")

    if bucket in CONFIRMED_BUCKETS and not finding.get("validated", True):
        reasons.append("confirmed_bucket_not_validated")

    return sorted(set(reasons))


def enforce_zero_inference_contract(state_dir: str | Path, *, repair: bool = False) -> dict[str, Any]:
    state = Path(state_dir)
    manifest = build_tool_manifest(state)
    producers = set(manifest["producer_tools"])

    bucket_path = state / FINDING_BUCKET_FILE
    buckets = _load_json(bucket_path, {})
    if not isinstance(buckets, dict):
        return {
            "status": "fail",
            "reason": "missing_or_invalid_bucket_file",
            "violations": [{"reason": "missing_or_invalid_bucket_file"}],
        }

    violations: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []

    for bucket, rows in list(buckets.items()):
        if not isinstance(rows, list):
            continue
        for idx, finding in enumerate(rows):
            if not isinstance(finding, dict):
                continue

            fid = _finding_id(finding, f"{bucket}:{idx}")
            reasons = classify_violation(bucket, finding, producers)
            if reasons:
                violations.append({
                    "id": fid,
                    "bucket": bucket,
                    "index": idx,
                    "reasons": reasons,
                    "title": finding.get("title") or finding.get("name") or "",
                })

    if repair and violations:
        to_move: set[tuple[str, int]] = {
            (str(v["bucket"]), int(v["index"]))
            for v in violations
            if v["bucket"] in PROMOTED_BUCKETS
        }

        moved = []
        for bucket in list(buckets.keys()):
            rows = buckets.get(bucket)
            if not isinstance(rows, list):
                continue

            kept = []
            for idx, finding in enumerate(rows):
                if not isinstance(finding, dict):
                    kept.append(finding)
                    continue

                if (bucket, idx) in to_move:
                    fid = _finding_id(finding, f"{bucket}:{idx}")
                    reasons = [
                        v["reasons"]
                        for v in violations
                        if v["bucket"] == bucket and v["index"] == idx
                    ]
                    finding = dict(finding)
                    finding["zero_inference_contract_routed"] = True
                    finding["zero_inference_contract_reason"] = reasons[0] if reasons else ["policy_violation"]
                    finding["disposition"] = "inconclusive_unresolved"
                    moved.append(finding)
                    audit_rows.append({
                        "id": fid,
                        "from_bucket": bucket,
                        "to_bucket": INCONCLUSIVE_BUCKET,
                        "reasons": finding["zero_inference_contract_reason"],
                    })
                else:
                    kept.append(finding)

            buckets[bucket] = kept

        buckets.setdefault(INCONCLUSIVE_BUCKET, [])
        existing_ids = {
            _finding_id(x, "")
            for x in buckets[INCONCLUSIVE_BUCKET]
            if isinstance(x, dict)
        }

        for finding in moved:
            fid = _finding_id(finding, "")
            if fid and fid in existing_ids:
                continue
            buckets[INCONCLUSIVE_BUCKET].append(finding)

        _write_json(bucket_path, buckets)

        if audit_rows:
            audit_path = state / AUDIT_FILE
            prior = _load_json(audit_path, [])
            if not isinstance(prior, list):
                prior = []
            prior.extend(audit_rows)
            _write_json(audit_path, prior)

        return enforce_zero_inference_contract(state, repair=False)

    status = "pass" if not violations else "fail"
    return {
        "status": status,
        "producer_tools": manifest["producer_tools"],
        "nonproducer_tools": manifest["nonproducer_tools"],
        "violations": violations,
        "violation_count": len(violations),
    }

# SIFT_ZERO_INFERENCE_STRICT_LANGUAGE_V2
# Promoted findings must be direct observations, not probability language.
STRICT_INFERENCE_RE_V2 = re.compile(
    "|".join(
        [
            r"\bguess(?:ed|es|ing)?\b",
            r"\bassum(?:e|ed|es|ing|ption|ptions)\b",
            r"\bprobably\b",
            r"\bpossible\b",
            r"\bpossibly\b",
            r"\bperhaps\b",
            r"\bappears?\b",
            r"\bseems?\b",
            r"\bsuggest(?:s|ed|ing|ion|ions)?\b",
            r"\blikely\b",
            r"\bmay\b",
            r"\bmight\b",
            r"\bcould\b",
            r"\binfer(?:red|ence|ences|ring)?\b",
            r"\bnot\s+conclusive\b",
            r"\bnot\s+definitive\b",
            r"\bambiguous\b",
        ]
    ),
    re.I,
)


def _has_inference_language(finding: dict[str, Any]) -> list[str]:  # type: ignore[override]
    hits: list[str] = []
    for text in _collect_human_text(finding):
        match = STRICT_INFERENCE_RE_V2.search(text or "")
        if match:
            hits.append(match.group(0))
    return hits
