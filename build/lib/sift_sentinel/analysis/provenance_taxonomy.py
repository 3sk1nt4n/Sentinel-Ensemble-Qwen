from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

# SIFT_PROVENANCE_TAXONOMY_V1
#
# Universal rule:
#   - tool fields may contain only real data-producing forensic tools from this run
#   - validation engines, deterministic rules, AI phases, and EvidenceDB are not tools
#   - zero/not-applicable/error/timeout/unavailable tools are not hit tools
#
# This module is dataset-agnostic. It derives tool producer/non-producer status
# from current-run artifacts only: all_outputs.json and tool_outputs/*.json.

BAD_STATUSES = {
    "error",
    "failed",
    "failure",
    "timeout",
    "timed_out",
    "not_applicable",
    "unavailable",
    "tool_unavailable",
    "ok_no_records",
    "no_records",
    "empty",
    "skipped",
}

TOOL_LIST_FIELDS = {
    "source_tools",
    "claim_tools",
    "tools_hit",
    "hit_tools",
    "tools",
    "producer_tools",
    "evidence_tools",
}

TOOL_SCALAR_FIELDS = {
    "source_tool",
    "claim_tool",
    "tool",
    "tool_name",
    "producer_tool",
    "evidence_tool",
}

# These are provenance/rule/backend labels, not forensic data producers.
NON_TOOL_PROVENANCE = {
    "typed_evidence_db",
    "evidence_db",
    "reference_set",
    "validator",
    "typed_validator",
    "claim_validator",
    "report_validator",
    "check_ancestry",
    "ancestry_check",
    "ancestry_rule",
    "deterministic_rule",
    "rule_engine",
    "candidate_observations",
    "self_correction",
    "react",
    "ai_react",
    "llm",
    "ensemble",
    "confidence",
    "disposition",
    "synthesis",
    "report_generation",
}

# Tool-name aliases, not case-data aliases.
# Keep this list about tool spelling/canonicalization only.
CANONICAL_ALIASES = {
    "tool_parse_appcompatcacheparser": "run_appcompatcacheparser",
    "parse_appcompatcacheparser": "run_appcompatcacheparser",
    "appcompatcacheparser": "run_appcompatcacheparser",
    "tool_run_appcompatcacheparser": "run_appcompatcacheparser",
    "tool_vol_svescan": "vol_svcscan",
    "vol_svescan": "vol_svcscan",
}

REAL_TOOL_PREFIXES = (
    "vol_",
    "parse_",
    "run_",
    "extract_",
    "decode_",
    "get_",
    "tool_vol_",
    "tool_parse_",
    "tool_run_",
    "tool_extract_",
    "tool_decode_",
    "tool_get_",
)


def _norm_label(value: Any) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    s = s.replace("-", "_").replace(" ", "_")
    while "__" in s:
        s = s.replace("__", "_")
    return s.lower()


def canonical_tool_name(value: Any) -> str:
    raw = _norm_label(value)
    if not raw:
        return ""
    if raw in CANONICAL_ALIASES:
        return CANONICAL_ALIASES[raw]
    if raw.startswith("tool_"):
        stripped = raw[5:]
        return CANONICAL_ALIASES.get(stripped, stripped)
    return CANONICAL_ALIASES.get(raw, raw)


def _records_from_payload(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("records", "data", "rows", "items", "results"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    # Some wrappers return {"result": {"records": [...]}}
    for key in ("result", "output", "tool_output"):
        value = payload.get(key)
        recs = _records_from_payload(value)
        if recs:
            return recs
    return []


def _record_count(payload: Any) -> int:
    if isinstance(payload, list):
        return len(payload)
    if not isinstance(payload, dict):
        return 0
    for key in ("record_count", "records_count", "count", "row_count", "num_records"):
        value = payload.get(key)
        if isinstance(value, int):
            return max(0, value)
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return len(_records_from_payload(payload))


def _status(payload: Any) -> str:
    if not isinstance(payload, dict):
        return "ok" if isinstance(payload, list) and payload else ""
    for key in ("status", "state", "result_status"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return _norm_label(value)
    # A dict with records and no explicit bad status is usable.
    return "ok" if _record_count(payload) > 0 else ""


def _tool_from_payload_or_name(name: str, payload: Any) -> str:
    if isinstance(payload, dict):
        for key in ("tool", "tool_name", "name", "plugin", "id"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return canonical_tool_name(value)
    return canonical_tool_name(name)


def _merge_manifest_entry(manifest: dict[str, dict[str, Any]], tool: str, payload: Any, source: str) -> None:
    tool = canonical_tool_name(tool)
    if not tool:
        return

    count = _record_count(payload)
    status = _status(payload)
    is_bad = status in BAD_STATUSES
    producer = count > 0 and not is_bad

    cur = manifest.setdefault(
        tool,
        {
            "tool": tool,
            "record_count": 0,
            "statuses": set(),
            "producer": False,
            "sources": set(),
        },
    )
    cur["record_count"] = max(int(cur.get("record_count") or 0), count)
    if status:
        cur["statuses"].add(status)
    cur["producer"] = bool(cur.get("producer")) or producer
    cur["sources"].add(source)


def load_tool_manifest(state_dir: str | os.PathLike[str]) -> dict[str, dict[str, Any]]:
    state = Path(state_dir)
    manifest: dict[str, dict[str, Any]] = {}

    all_outputs = state / "all_outputs.json"
    if all_outputs.exists():
        try:
            data = json.loads(all_outputs.read_text(errors="replace"))
        except Exception:
            data = None

        if isinstance(data, dict):
            for key, payload in data.items():
                if isinstance(payload, (dict, list)):
                    tool = _tool_from_payload_or_name(key, payload)
                    _merge_manifest_entry(manifest, tool, payload, "all_outputs")
        elif isinstance(data, list):
            for idx, payload in enumerate(data):
                if isinstance(payload, dict):
                    tool = _tool_from_payload_or_name(str(idx), payload)
                    _merge_manifest_entry(manifest, tool, payload, "all_outputs")

    tool_outputs = state / "tool_outputs"
    if tool_outputs.exists():
        for p in sorted(tool_outputs.glob("*.json")):
            try:
                payload = json.loads(p.read_text(errors="replace"))
            except Exception:
                continue
            tool = _tool_from_payload_or_name(p.stem, payload)
            _merge_manifest_entry(manifest, tool, payload, f"tool_outputs/{p.name}")

    # Convert sets to sorted lists for JSON safety.
    for info in manifest.values():
        info["statuses"] = sorted(info.get("statuses") or [])
        info["sources"] = sorted(info.get("sources") or [])

    return manifest


def classify_provenance_label(value: Any, manifest: dict[str, dict[str, Any]]) -> dict[str, Any]:
    raw = str(value or "").strip()
    canon = canonical_tool_name(raw)

    if not canon:
        return {"raw": raw, "canonical": "", "class": "empty", "is_valid_tool": False}

    if canon in NON_TOOL_PROVENANCE:
        return {
            "raw": raw,
            "canonical": canon,
            "class": "non_tool_provenance",
            "is_valid_tool": False,
        }

    info = manifest.get(canon)
    if info:
        if bool(info.get("producer")):
            return {
                "raw": raw,
                "canonical": canon,
                "class": "real_data_producing_tool",
                "is_valid_tool": True,
                "record_count": int(info.get("record_count") or 0),
                "statuses": info.get("statuses") or [],
            }
        return {
            "raw": raw,
            "canonical": canon,
            "class": "zero_or_nonhit_tool",
            "is_valid_tool": False,
            "record_count": int(info.get("record_count") or 0),
            "statuses": info.get("statuses") or [],
        }

    if canon.startswith(REAL_TOOL_PREFIXES):
        return {
            "raw": raw,
            "canonical": canon,
            "class": "absent_tool",
            "is_valid_tool": False,
        }

    return {
        "raw": raw,
        "canonical": canon,
        "class": "unknown_non_tool_or_unregistered",
        "is_valid_tool": False,
    }


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, str):
        # Avoid splitting human prose. Only split obvious CSV-like tool fields.
        if "," in value and " " not in value.replace(",", ""):
            return [x.strip() for x in value.split(",") if x.strip()]
        return [value]
    return [value]


def _append_unique_list(obj: dict[str, Any], key: str, value: Any) -> None:
    if not value:
        return
    cur = obj.get(key)
    if not isinstance(cur, list):
        cur = []
    if value not in cur:
        cur.append(value)
    obj[key] = cur


def _move_non_tool_label(finding: dict[str, Any], label: str) -> None:
    if label in {"typed_evidence_db", "evidence_db", "reference_set"}:
        _append_unique_list(finding, "validation_backends", label)
    elif "ancestry" in label or label.endswith("_rule") or label == "deterministic_rule":
        _append_unique_list(finding, "rule_ids", label)
    else:
        _append_unique_list(finding, "provenance_non_tool", label)


def sanitize_finding_tool_refs(
    finding: dict[str, Any],
    manifest: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    stats = {
        "removed_refs": 0,
        "canonicalized_refs": 0,
        "moved_non_tool_refs": 0,
        "bad_refs": [],
        "valid_tools": set(),
    }

    if not isinstance(finding, dict):
        return stats

    removed_detail = finding.get("removed_invalid_tool_refs")
    if not isinstance(removed_detail, list):
        removed_detail = []

    # List-valued tool fields.
    for field in sorted(TOOL_LIST_FIELDS):
        if field not in finding:
            continue

        original = _as_list(finding.get(field))
        cleaned: list[str] = []

        for item in original:
            cls = classify_provenance_label(item, manifest)
            canon = cls["canonical"]

            if cls["is_valid_tool"]:
                if canon not in cleaned:
                    cleaned.append(canon)
                    stats["valid_tools"].add(canon)
                if str(item) != canon:
                    stats["canonicalized_refs"] += 1
                continue

            if cls["class"] == "non_tool_provenance":
                _move_non_tool_label(finding, canon)
                stats["moved_non_tool_refs"] += 1
            else:
                removed_detail.append(
                    {
                        "field": field,
                        "raw": str(item),
                        "canonical": canon,
                        "class": cls["class"],
                    }
                )
                stats["removed_refs"] += 1
                stats["bad_refs"].append((field, item, cls["class"]))

        if cleaned:
            finding[field] = cleaned
        else:
            finding.pop(field, None)

    # Scalar tool fields.
    for field in sorted(TOOL_SCALAR_FIELDS):
        if field not in finding:
            continue

        item = finding.get(field)
        cls = classify_provenance_label(item, manifest)
        canon = cls["canonical"]

        if cls["is_valid_tool"]:
            finding[field] = canon
            stats["valid_tools"].add(canon)
            if str(item) != canon:
                stats["canonicalized_refs"] += 1
            continue

        if cls["class"] == "non_tool_provenance":
            _move_non_tool_label(finding, canon)
            stats["moved_non_tool_refs"] += 1
        else:
            removed_detail.append(
                {
                    "field": field,
                    "raw": str(item),
                    "canonical": canon,
                    "class": cls["class"],
                }
            )
            stats["removed_refs"] += 1
            stats["bad_refs"].append((field, item, cls["class"]))

        finding.pop(field, None)

    # Claims may also carry tool refs.
    claims = finding.get("claims")
    if isinstance(claims, list):
        for claim in claims:
            if not isinstance(claim, dict):
                continue

            for field in sorted(TOOL_LIST_FIELDS):
                if field not in claim:
                    continue

                cleaned: list[str] = []
                for item in _as_list(claim.get(field)):
                    cls = classify_provenance_label(item, manifest)
                    canon = cls["canonical"]

                    if cls["is_valid_tool"]:
                        if canon not in cleaned:
                            cleaned.append(canon)
                            stats["valid_tools"].add(canon)
                        if str(item) != canon:
                            stats["canonicalized_refs"] += 1
                    elif cls["class"] == "non_tool_provenance":
                        _append_unique_list(claim, "provenance_non_tool", canon)
                        stats["moved_non_tool_refs"] += 1
                    else:
                        removed_detail.append(
                            {
                                "field": f"claims.{field}",
                                "raw": str(item),
                                "canonical": canon,
                                "class": cls["class"],
                            }
                        )
                        stats["removed_refs"] += 1
                        stats["bad_refs"].append((f"claims.{field}", item, cls["class"]))

                if cleaned:
                    claim[field] = cleaned
                else:
                    claim.pop(field, None)

            for field in sorted(TOOL_SCALAR_FIELDS):
                if field not in claim:
                    continue

                item = claim.get(field)
                cls = classify_provenance_label(item, manifest)
                canon = cls["canonical"]

                if cls["is_valid_tool"]:
                    claim[field] = canon
                    stats["valid_tools"].add(canon)
                    if str(item) != canon:
                        stats["canonicalized_refs"] += 1
                elif cls["class"] == "non_tool_provenance":
                    _append_unique_list(claim, "provenance_non_tool", canon)
                    stats["moved_non_tool_refs"] += 1
                    claim.pop(field, None)
                else:
                    removed_detail.append(
                        {
                            "field": f"claims.{field}",
                            "raw": str(item),
                            "canonical": canon,
                            "class": cls["class"],
                        }
                    )
                    stats["removed_refs"] += 1
                    stats["bad_refs"].append((f"claims.{field}", item, cls["class"]))
                    claim.pop(field, None)

    # Reconstruct top-level source_tools from all valid tools seen.
    existing = set(_as_list(finding.get("source_tools")))
    all_valid = sorted(existing | set(stats["valid_tools"]))
    if all_valid:
        finding["source_tools"] = all_valid

    if removed_detail:
        finding["removed_invalid_tool_refs"] = removed_detail

    return stats


def _iter_findings_container(container: Any):
    if isinstance(container, dict):
        # disposition buckets
        if any(isinstance(container.get(k), list) for k in (
            "confirmed_malicious_atomic",
            "suspicious_needs_review",
            "inconclusive_unresolved",
            "benign_or_false_positive",
            "synthesis_narrative",
        )):
            for key, value in container.items():
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            yield item
            return

        # single finding
        if "claims" in container or "source_tools" in container or "title" in container:
            yield container

        # nested fallback
        for value in container.values():
            yield from _iter_findings_container(value)

    elif isinstance(container, list):
        for item in container:
            yield from _iter_findings_container(item)


def _has_real_tool(finding: dict[str, Any], manifest: dict[str, dict[str, Any]]) -> bool:
    fields = []
    for field in TOOL_LIST_FIELDS:
        fields.extend(_as_list(finding.get(field)))
    for field in TOOL_SCALAR_FIELDS:
        if field in finding:
            fields.append(finding.get(field))
    for item in fields:
        if classify_provenance_label(item, manifest)["is_valid_tool"]:
            return True

    claims = finding.get("claims")
    if isinstance(claims, list):
        for claim in claims:
            if not isinstance(claim, dict):
                continue
            for field in TOOL_LIST_FIELDS:
                for item in _as_list(claim.get(field)):
                    if classify_provenance_label(item, manifest)["is_valid_tool"]:
                        return True
            for field in TOOL_SCALAR_FIELDS:
                if field in claim and classify_provenance_label(claim.get(field), manifest)["is_valid_tool"]:
                    return True
    return False


def _route_bucket_payload(payload: dict[str, Any], manifest: dict[str, dict[str, Any]]) -> int:
    """Move no-real-tool actionable/confirmed rows to inconclusive.

    This is a safety net. It does not decide maliciousness; it only prevents a
    finding with no real tool provenance from staying actionable/confirmed.
    """
    if not isinstance(payload, dict):
        return 0

    moved = 0
    inconclusive = payload.setdefault("inconclusive_unresolved", [])
    if not isinstance(inconclusive, list):
        inconclusive = []
        payload["inconclusive_unresolved"] = inconclusive

    for source_bucket in ("confirmed_malicious_atomic", "suspicious_needs_review"):
        rows = payload.get(source_bucket)
        if not isinstance(rows, list):
            continue
        keep = []
        for finding in rows:
            if not isinstance(finding, dict):
                keep.append(finding)
                continue
            if _has_real_tool(finding, manifest):
                keep.append(finding)
                continue
            finding["disposition_reason"] = "no_real_data_producing_tool_provenance"
            finding["forced_inconclusive_by"] = "provenance_taxonomy"
            inconclusive.append(finding)
            moved += 1
        payload[source_bucket] = keep

    # De-duplicate inconclusive by id/title pair.
    seen = set()
    deduped = []
    for finding in inconclusive:
        if not isinstance(finding, dict):
            deduped.append(finding)
            continue
        fid = finding.get("finding_id") or finding.get("id")
        if fid is not None:
            if fid in seen:
                continue
            seen.add(fid)
        deduped.append(finding)
    payload["inconclusive_unresolved"] = deduped
    return moved


def _finding_artifact_paths(state: Path) -> list[Path]:
    names = [
        "findings.json",
        "findings_validated.json",
        "findings_final.json",
        "finding_disposition_buckets.json",
        "pipeline_summary.json",
    ]
    return [state / n for n in names if (state / n).exists()]


def enforce_state_provenance_taxonomy(
    state_dir: str | os.PathLike[str],
    *,
    repair: bool = False,
    route_nohit: bool = True,
) -> dict[str, Any]:
    state = Path(state_dir)
    manifest = load_tool_manifest(state)

    result = {
        "status": "pass",
        "state": str(state),
        "manifest_tools": len(manifest),
        "producer_tools": sorted(k for k, v in manifest.items() if v.get("producer")),
        "nonproducer_tools": sorted(k for k, v in manifest.items() if not v.get("producer")),
        "files_scanned": 0,
        "findings_scanned": 0,
        "removed_refs": 0,
        "canonicalized_refs": 0,
        "moved_non_tool_refs": 0,
        "routed_nohit_to_inconclusive": 0,
        "bad_refs": [],
    }

    for path in _finding_artifact_paths(state):
        try:
            payload = json.loads(path.read_text(errors="replace"))
        except Exception as e:
            result["status"] = "fail"
            result.setdefault("errors", []).append(f"{path.name}: {e}")
            continue

        result["files_scanned"] += 1

        for finding in _iter_findings_container(payload):
            result["findings_scanned"] += 1
            stats = sanitize_finding_tool_refs(finding, manifest)
            result["removed_refs"] += int(stats.get("removed_refs") or 0)
            result["canonicalized_refs"] += int(stats.get("canonicalized_refs") or 0)
            result["moved_non_tool_refs"] += int(stats.get("moved_non_tool_refs") or 0)
            for field, item, cls in stats.get("bad_refs") or []:
                result["bad_refs"].append(
                    {
                        "file": path.name,
                        "field": field,
                        "raw": str(item),
                        "class": cls,
                    }
                )

        if path.name == "finding_disposition_buckets.json" and route_nohit:
            result["routed_nohit_to_inconclusive"] += _route_bucket_payload(payload, manifest)

        if repair:
            path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    if result["bad_refs"] and not repair:
        result["status"] = "fail"

    if repair:
        # Verify clean after repair.
        verify = enforce_state_provenance_taxonomy(state, repair=False, route_nohit=route_nohit)
        if verify.get("status") != "pass":
            result["status"] = "fail"
            result["post_repair_bad_refs"] = verify.get("bad_refs") or []
        else:
            result["status"] = "pass"

    return result


# Backward-compatible name used by existing gates.
def enforce_state_tool_hit_integrity(
    state_dir: str | os.PathLike[str],
    *,
    repair: bool = False,
    route_nohit: bool = True,
    **_: Any,
) -> dict[str, Any]:
    return enforce_state_provenance_taxonomy(
        state_dir,
        repair=repair,
        route_nohit=route_nohit,
    )


# SIFT_PROVENANCE_ACTIVE_STATE_RESOLVER_V1
try:
    _sift_prov_prior_enforce_state_provenance_taxonomy_v1 = enforce_state_provenance_taxonomy
except NameError:  # pragma: no cover
    _sift_prov_prior_enforce_state_provenance_taxonomy_v1 = None


def enforce_state_provenance_taxonomy(*args, **kwargs):
    from sift_sentinel.analysis.state_dir_resolver import resolve_state_dir

    state_dir = kwargs.get("state_dir")
    args_list = list(args)

    if state_dir is None and args_list:
        first = args_list[0]
        try:
            if isinstance(first, (str, bytes)) or hasattr(first, "__fspath__"):
                state_dir = first
                args_list = args_list[1:]
        except Exception:
            pass

    resolved = resolve_state_dir(state_dir, require_existing=True, require_marker=False)
    if not resolved:
        result = {
            "status": "fail",
            "reason": "active_state_dir_not_resolved",
            "removed_refs": 0,
            "canonicalized_refs": 0,
            "moved_non_tool_refs": 0,
            "routed_nohit": 0,
        }
        if kwargs.get("fail"):
            raise RuntimeError("PROVENANCE_TAXONOMY_GATE=FAIL reason=active_state_dir_not_resolved")
        return result

    kwargs["state_dir"] = resolved
    if _sift_prov_prior_enforce_state_provenance_taxonomy_v1 is None:
        return {"status": "pass", "state_dir": resolved}

    return _sift_prov_prior_enforce_state_provenance_taxonomy_v1(*args_list, **kwargs)

