from __future__ import annotations

import json
import os
from functools import wraps
from pathlib import Path
from typing import Any

BAD_STATUSES = {
    "error",
    "failed",
    "failure",
    "timeout",
    "timed_out",
    "not_applicable",
    "not-applicable",
    "not applicable",
    "skipped",
    "unavailable",
}

TOOL_PREFIXES = (
    "vol_",
    "parse_",
    "run_",
    "get_",
    "extract_",
    "decode_",
    "tool_",
)

TOOL_LIST_FIELDS = {
    "source_tools",
    "claim_tools",
    "tools_hit",
    "hit_tools",
    "tools",
    "forensic_tools",
    "supporting_tools",
    "evidence_tools",
    "validated_tools",
}

TOOL_SCALAR_FIELDS = {
    "tool",
    "source_tool",
    "claim_tool",
    "producer_tool",
    "evidence_tool",
    "tool_name",
}

COUNT_FIELDS = (
    "record_count",
    "records_count",
    "count",
    "total",
    "total_records",
    "source_total",
    "selected_total",
)

RECORD_FIELDS = (
    "records",
    "results",
    "items",
    "rows",
    "events",
    "findings",
    "data",
)


def canonical_tool_name(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    name = value.strip()
    if name.startswith("tool_"):
        name = name[5:]
    return name


def looks_tool_name(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    name = value.strip()
    if not name:
        return False
    return name.startswith(TOOL_PREFIXES)


def _lower_status(out: Any) -> str:
    if not isinstance(out, dict):
        return ""
    return str(out.get("status") or out.get("state") or out.get("result_status") or "").strip().lower()


def _bad_status(out: Any) -> bool:
    status = _lower_status(out)
    if status in BAD_STATUSES:
        return True
    if "not_applicable" in status or "not applicable" in status:
        return True
    if "timeout" in status:
        return True
    if "error" in status and status != "ok":
        return True
    return False


def _safe_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        value = value.strip()
        if value.isdigit():
            return int(value)
    return None


def record_count(out: Any) -> int:
    if out is None:
        return 0
    if isinstance(out, list):
        return len(out)
    if not isinstance(out, dict):
        return 0

    if _bad_status(out):
        return 0

    for key in COUNT_FIELDS:
        if key in out:
            n = _safe_int(out.get(key))
            if n is not None:
                return max(0, n)

    for key in RECORD_FIELDS:
        if key not in out:
            continue
        value = out.get(key)
        if isinstance(value, list):
            return len(value)
        if isinstance(value, dict):
            # Treat mapping-style records as data only if not just metadata/status.
            metadataish = {"status", "reason", "evidence_path", "source_files", "record_count"}
            if set(value.keys()).issubset(metadataish):
                continue
            return len(value)
        n = _safe_int(value)
        if n is not None:
            return max(0, n)

    return 0


def _iter_tool_output_pairs(obj: Any, depth: int = 0):
    if depth > 4:
        return

    if isinstance(obj, dict):
        # Common structure: {"vol_pstree": {"records": [...]}, ...}
        direct_hits = 0
        for key, value in obj.items():
            if looks_tool_name(key) and isinstance(value, (dict, list)):
                direct_hits += 1
                yield canonical_tool_name(key), value

        if direct_hits:
            return

        # Common structure: {"tool": "vol_pstree", "records": [...]}
        name = obj.get("tool") or obj.get("tool_name") or obj.get("name")
        if looks_tool_name(name):
            yield canonical_tool_name(name), obj
            return

        for key in ("all_outputs", "tool_outputs", "outputs", "results"):
            value = obj.get(key)
            if isinstance(value, (dict, list)):
                yield from _iter_tool_output_pairs(value, depth + 1)

    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                yield from _iter_tool_output_pairs(item, depth + 1)


def build_hit_maps(all_outputs: Any) -> tuple[dict[str, int], dict[str, int]]:
    counts: dict[str, int] = {}
    for name, out in _iter_tool_output_pairs(all_outputs):
        if not name:
            continue
        counts[name] = max(counts.get(name, 0), record_count(out))

    hit_map = {name: n for name, n in counts.items() if n > 0}

    # Accept both canonical and tool_ aliases for lookups.
    expanded: dict[str, int] = {}
    for name, n in hit_map.items():
        expanded[name] = n
        expanded[f"tool_{name}"] = n

    zero_or_nonhit = {name: n for name, n in counts.items() if n <= 0}
    for name in list(zero_or_nonhit):
        zero_or_nonhit[f"tool_{name}"] = zero_or_nonhit[name]

    return expanded, zero_or_nonhit


def _filter_tool_sequence(values: Any, hit_map: dict[str, int]) -> tuple[Any, int]:
    if not isinstance(values, list):
        return values, 0

    kept = []
    removed = 0
    for value in values:
        if looks_tool_name(value):
            canon = canonical_tool_name(value)
            if canon in hit_map or value in hit_map:
                kept.append(value)
            else:
                removed += 1
        else:
            kept.append(value)
    return kept, removed


def _filter_tool_scalar(value: Any, hit_map: dict[str, int]) -> tuple[Any, int]:
    if looks_tool_name(value):
        canon = canonical_tool_name(value)
        if canon in hit_map or value in hit_map:
            return value, 0
        return None, 1
    return value, 0


def _is_finding_like(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    return bool(
        obj.get("id")
        and (
            "claims" in obj
            or "title" in obj
            or "name" in obj
            or TOOL_LIST_FIELDS.intersection(obj.keys())
            or TOOL_SCALAR_FIELDS.intersection(obj.keys())
        )
    )


def effective_hit_tools(finding: dict[str, Any], hit_map: dict[str, int]) -> set[str]:
    out: set[str] = set()

    def add(value: Any):
        if isinstance(value, str) and looks_tool_name(value):
            canon = canonical_tool_name(value)
            if canon in hit_map or value in hit_map:
                out.add(canon)

    for key in TOOL_LIST_FIELDS:
        value = finding.get(key)
        if isinstance(value, list):
            for item in value:
                add(item)

    for key in TOOL_SCALAR_FIELDS:
        add(finding.get(key))

    for claim in finding.get("claims") or []:
        if isinstance(claim, dict):
            for key in TOOL_LIST_FIELDS:
                value = claim.get(key)
                if isinstance(value, list):
                    for item in value:
                        add(item)
            for key in TOOL_SCALAR_FIELDS:
                add(claim.get(key))

    return out


def sanitize_finding_inplace(finding: dict[str, Any], hit_map: dict[str, int]) -> int:
    removed = 0

    for key in list(TOOL_LIST_FIELDS):
        if key in finding:
            filtered, n = _filter_tool_sequence(finding.get(key), hit_map)
            finding[key] = filtered
            removed += n

    for key in list(TOOL_SCALAR_FIELDS):
        if key in finding:
            filtered, n = _filter_tool_scalar(finding.get(key), hit_map)
            if filtered is None and n:
                finding.pop(key, None)
            else:
                finding[key] = filtered
            removed += n

    claims = finding.get("claims")
    if isinstance(claims, list):
        for claim in claims:
            if isinstance(claim, dict):
                for key in list(TOOL_LIST_FIELDS):
                    if key in claim:
                        filtered, n = _filter_tool_sequence(claim.get(key), hit_map)
                        claim[key] = filtered
                        removed += n
                for key in list(TOOL_SCALAR_FIELDS):
                    if key in claim:
                        filtered, n = _filter_tool_scalar(claim.get(key), hit_map)
                        if filtered is None and n:
                            claim.pop(key, None)
                        else:
                            claim[key] = filtered
                        removed += n

    if removed:
        # Store only a count; do not preserve zero-hit tool names inside final finding JSON.
        meta = finding.setdefault("_tool_hit_integrity", {})
        if isinstance(meta, dict):
            meta["zero_or_nonhit_tool_refs_removed"] = int(meta.get("zero_or_nonhit_tool_refs_removed") or 0) + removed

    return removed


def sanitize_findings_inplace(obj: Any, hit_map: dict[str, int]) -> int:
    removed = 0
    if isinstance(obj, list):
        for item in obj:
            removed += sanitize_findings_inplace(item, hit_map)
        return removed

    if isinstance(obj, dict):
        if _is_finding_like(obj):
            removed += sanitize_finding_inplace(obj, hit_map)

        for value in obj.values():
            if isinstance(value, (dict, list)):
                removed += sanitize_findings_inplace(value, hit_map)

    return removed


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(errors="ignore"))


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False) + "\n")


def _merged_outputs_from_state(state_dir: Path) -> dict[str, Any]:
    merged: dict[str, Any] = {}

    all_outputs = state_dir / "all_outputs.json"
    if all_outputs.exists():
        obj = _load_json(all_outputs)
        if isinstance(obj, dict):
            merged.update(obj)

    tool_dir = state_dir / "tool_outputs"
    if tool_dir.exists():
        for p in sorted(tool_dir.glob("*.json")):
            try:
                merged[p.stem] = _load_json(p)
            except Exception:
                continue

    return merged


def _bucket_findings(bucket_obj: Any):
    if isinstance(bucket_obj, dict):
        for key, value in bucket_obj.items():
            if isinstance(value, list):
                for finding in value:
                    if isinstance(finding, dict):
                        yield key, finding


def enforce_state_dir_tool_hit_integrity(state_dir: str | Path, fail: bool = True) -> dict[str, Any]:
    state = Path(state_dir)
    outputs = _merged_outputs_from_state(state)
    hit_map, zero_map = build_hit_maps(outputs)

    result = {
        "state": str(state),
        "hit_tools": sorted({canonical_tool_name(k) for k in hit_map if not k.startswith("tool_")}),
        "zero_or_nonhit_tools": sorted({canonical_tool_name(k) for k in zero_map if not k.startswith("tool_")}),
        "removed_refs": 0,
        "routed_nohit_to_inconclusive": 0,
        "bad_refs_after": [],
    }

    if not hit_map:
        result["status"] = "no_hit_map"
        return result

    json_files = [
        state / "findings_validated.json",
        state / "findings_final.json",
        state / "pipeline_summary.json",
    ]

    for p in json_files:
        if not p.exists():
            continue
        try:
            obj = _load_json(p)
            removed = sanitize_findings_inplace(obj, hit_map)
            result["removed_refs"] += removed
            if removed:
                _write_json(p, obj)
        except Exception as exc:
            result.setdefault("errors", []).append(f"{p.name}: {exc}")

    buckets_path = state / "finding_disposition_buckets.json"
    if buckets_path.exists():
        try:
            buckets = _load_json(buckets_path)
            result["removed_refs"] += sanitize_findings_inplace(buckets, hit_map)

            if isinstance(buckets, dict):
                inconclusive = buckets.setdefault("inconclusive_unresolved", [])
                seen_inconclusive_ids = {f.get("id") for f in inconclusive if isinstance(f, dict)}

                for bucket_name in ("confirmed_malicious_atomic", "suspicious_needs_review"):
                    items = buckets.get(bucket_name)
                    if not isinstance(items, list):
                        continue
                    kept = []
                    for finding in items:
                        if not isinstance(finding, dict):
                            kept.append(finding)
                            continue
                        if effective_hit_tools(finding, hit_map):
                            kept.append(finding)
                            continue
                        fid = finding.get("id")
                        finding["_tool_hit_integrity"] = {
                            "routed_to_inconclusive": True,
                            "reason": "no data-producing source tool remained after zero/non-hit filtering",
                        }
                        if fid not in seen_inconclusive_ids:
                            inconclusive.append(finding)
                            seen_inconclusive_ids.add(fid)
                            result["routed_nohit_to_inconclusive"] += 1
                    buckets[bucket_name] = kept

            _write_json(buckets_path, buckets)
        except Exception as exc:
            result.setdefault("errors", []).append(f"{buckets_path.name}: {exc}")

    bad = check_state_dir_tool_hit_integrity(state, return_bad=True)
    result["bad_refs_after"] = bad
    result["status"] = "pass" if not bad else "fail"

    if fail and bad:
        raise AssertionError(f"zero/non-hit tool references remain in findings: {bad[:10]}")

    return result


def latest_state_dir() -> Path | None:
    roots = sorted(Path("/tmp").glob("sift-sentinel-run-*"), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    return roots[0] if roots else None


def enforce_latest_state_tool_hit_integrity(fail: bool = False) -> dict[str, Any]:
    state = latest_state_dir()
    if not state:
        return {"status": "no_state"}
    return enforce_state_dir_tool_hit_integrity(state, fail=fail)


def _collect_tool_fields(obj: Any, path: str = "$"):
    if isinstance(obj, list):
        for idx, item in enumerate(obj):
            yield from _collect_tool_fields(item, f"{path}[{idx}]")
        return

    if not isinstance(obj, dict):
        return

    if _is_finding_like(obj):
        fid = obj.get("id")
        for key in TOOL_LIST_FIELDS:
            value = obj.get(key)
            if isinstance(value, list):
                for item in value:
                    if looks_tool_name(item):
                        yield fid, f"{path}.{key}", item
        for key in TOOL_SCALAR_FIELDS:
            value = obj.get(key)
            if looks_tool_name(value):
                yield fid, f"{path}.{key}", value

    for key, value in obj.items():
        if isinstance(value, (dict, list)):
            yield from _collect_tool_fields(value, f"{path}.{key}")


def check_state_dir_tool_hit_integrity(state_dir: str | Path, return_bad: bool = False):
    state = Path(state_dir)
    outputs = _merged_outputs_from_state(state)
    hit_map, zero_map = build_hit_maps(outputs)
    bad = []

    files = [
        state / "findings_validated.json",
        state / "findings_final.json",
        state / "finding_disposition_buckets.json",
        state / "pipeline_summary.json",
    ]

    for p in files:
        if not p.exists():
            continue
        try:
            obj = _load_json(p)
        except Exception:
            continue
        for fid, where, tool in _collect_tool_fields(obj):
            canon = canonical_tool_name(tool)
            if looks_tool_name(tool) and canon not in hit_map and tool not in hit_map:
                bad.append({"file": p.name, "finding_id": fid, "where": where, "tool": tool})

    if return_bad:
        return bad

    if bad:
        print(f"TOOL_HIT_INTEGRITY_GATE=FAIL bad_refs={len(bad)} state={state}")
        for item in bad[:40]:
            print(json.dumps(item, sort_keys=True))
        return False

    print(f"TOOL_HIT_INTEGRITY_GATE=PASS state={state}")
    return True


def _find_outputs_in_obj(obj: Any, depth: int = 0) -> Any | None:
    if depth > 4:
        return None
    if isinstance(obj, dict):
        pairs = list(_iter_tool_output_pairs(obj))
        if len(pairs) >= 2:
            return obj
        for key in ("all_outputs", "tool_outputs", "outputs"):
            if key in obj:
                found = _find_outputs_in_obj(obj[key], depth + 1)
                if found is not None:
                    return found
        for value in obj.values():
            if isinstance(value, (dict, list)):
                found = _find_outputs_in_obj(value, depth + 1)
                if found is not None:
                    return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_outputs_in_obj(item, depth + 1)
            if found is not None:
                return found
    return None


def _outputs_from_call(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any | None:
    for key in ("all_outputs", "tool_outputs", "outputs", "raw_outputs"):
        if key in kwargs:
            found = _find_outputs_in_obj(kwargs[key])
            if found is not None:
                return found

    for value in list(args) + list(kwargs.values()):
        found = _find_outputs_in_obj(value)
        if found is not None:
            return found

    return None


def install_module_wrappers(module_globals: dict[str, Any]) -> None:
    # Best-effort in-memory enforcement for validator/confidence/disposition functions.
    # The state-file enforcement remains the final hard gate.
    candidate_names = []
    for name, value in list(module_globals.items()):
        if not callable(value):
            continue
        lname = name.lower()
        if (
            ("finding" in lname and "validat" in lname)
            or ("confidence" in lname and ("score" in lname or "calibrat" in lname))
            or ("disposition" in lname and ("route" in lname or "write" in lname))
        ):
            candidate_names.append(name)

    for name in candidate_names:
        fn = module_globals.get(name)
        if getattr(fn, "_sift_tool_hit_integrity_wrapped", False):
            continue

        @wraps(fn)
        def wrapped(*args, __fn=fn, **kwargs):
            outputs = _outputs_from_call(args, kwargs)
            hit_map = {}
            if outputs is not None:
                hit_map, _ = build_hit_maps(outputs)
                if hit_map:
                    sanitize_findings_inplace(args, hit_map)
                    sanitize_findings_inplace(kwargs, hit_map)

            result = __fn(*args, **kwargs)

            if hit_map:
                sanitize_findings_inplace(result, hit_map)
            return result

        wrapped._sift_tool_hit_integrity_wrapped = True
        module_globals[name] = wrapped

# SIFT_TOOL_HIT_INTEGRITY_STRICT_CANONICAL_V4
# Universal provenance policy:
# - only tools that produced usable records may be cited as hit/source/claim tools
# - zero-record, not_applicable, error, timeout, unavailable, or absent tools are removed
# - known tool-name aliases canonicalize to the real producing tool
# - unsupported/no-hit findings are routed out of confirmed/actionable buckets

import json as _sift_v4_json
import os as _sift_v4_os
from pathlib import Path as _SiftV4Path
from typing import Any as _SiftV4Any

_SIFT_V4_BAD_STATUS_TERMS = {
    "error",
    "failed",
    "failure",
    "timeout",
    "not_applicable",
    "not applicable",
    "ok_no_records",
    "no_records",
    "no records",
    "unavailable",
    "absent",
    "missing",
    "derived_after_raw_cache_only",
}

_SIFT_V4_TOOL_PREFIXES = (
    "vol_",
    "parse_",
    "run_",
    "get_",
    "extract_",
    "decode_",
    "tool_",
)

_SIFT_V4_TOOL_REF_FIELDS = {
    "source_tool",
    "source_tools",
    "tool",
    "tools",
    "tools_hit",
    "hit_tools",
    "claim_tools",
    "evidence_tools",
    "validator_tools",
    "supporting_tools",
    "contributing_tools",
}

_SIFT_V4_BUCKET_KEYS = {
    "confirmed_malicious_atomic",
    "suspicious_needs_review",
    "benign_or_false_positive",
    "inconclusive_unresolved",
    "synthesis_narrative",
}


def canonical_tool_name(name: _SiftV4Any) -> str:
    if not isinstance(name, str):
        return ""
    v = name.strip().lower()
    if not v:
        return ""
    v = v.replace("-", "_").replace(" ", "_")
    while v.startswith("tool_"):
        v = v[5:]

    aliases = {
        # Eric Zimmerman style parser wrapper aliases.
        "appcompatcacheparser": "run_appcompatcacheparser",
        "parse_appcompatcacheparser": "run_appcompatcacheparser",
        "appcompatcache": "run_appcompatcacheparser",
        "shimcache": "run_appcompatcacheparser",
        "parse_shimcache": "run_appcompatcacheparser",

        "lecmd": "run_lecmd",
        "parse_lecmd": "run_lecmd",
        "lnk": "run_lecmd",
        "parse_lnk": "run_lecmd",

        "jlecmd": "run_jlecmd",
        "parse_jlecmd": "run_jlecmd",
        "jumplist": "run_jlecmd",
        "parse_jumplist": "run_jlecmd",

        "srumecmd": "run_srumecmd",
        "parse_srumecmd": "run_srumecmd",
        "srum": "run_srumecmd",
        "parse_srum": "run_srumecmd",
    }
    return aliases.get(v, v)


def _sift_v4_status(payload: _SiftV4Any) -> str:
    if isinstance(payload, dict):
        for k in ("status", "state", "tool_status", "result_status"):
            if k in payload and payload[k] is not None:
                return str(payload[k]).strip().lower()
        result = payload.get("result")
        if isinstance(result, dict):
            for k in ("status", "state"):
                if k in result and result[k] is not None:
                    return str(result[k]).strip().lower()
    return ""


def _sift_v4_record_count(payload: _SiftV4Any) -> int:
    if isinstance(payload, list):
        return len(payload)
    if not isinstance(payload, dict):
        return 0

    for k in ("records", "items", "rows", "events", "findings"):
        v = payload.get(k)
        if isinstance(v, list):
            return len(v)
        if isinstance(v, dict):
            rv = v.get("records")
            if isinstance(rv, list):
                return len(rv)

    result = payload.get("result")
    if isinstance(result, list):
        return len(result)
    if isinstance(result, dict):
        for k in ("records", "items", "rows"):
            v = result.get(k)
            if isinstance(v, list):
                return len(v)

    for k in ("record_count", "records_count", "count", "total_records", "total"):
        if k in payload:
            try:
                return int(payload[k])
            except Exception:
                pass

    meta = payload.get("metadata")
    if isinstance(meta, dict):
        for k in ("record_count", "records_count", "count", "total_records"):
            if k in meta:
                try:
                    return int(meta[k])
                except Exception:
                    pass

    return 0


def _sift_v4_is_bad_status(status: str) -> bool:
    s = (status or "").strip().lower()
    if not s:
        return False
    return any(term in s for term in _SIFT_V4_BAD_STATUS_TERMS)


def _sift_v4_is_hit_payload(payload: _SiftV4Any) -> bool:
    return _sift_v4_record_count(payload) > 0 and not _sift_v4_is_bad_status(_sift_v4_status(payload))


def build_hit_maps(outputs: dict[str, _SiftV4Any] | None) -> tuple[dict[str, dict], dict[str, dict]]:
    hit: dict[str, dict] = {}
    zero: dict[str, dict] = {}
    if not isinstance(outputs, dict):
        return hit, zero

    for raw_name, payload in outputs.items():
        tool = canonical_tool_name(raw_name)
        if not tool:
            continue

        info = {
            "raw_name": raw_name,
            "canonical_name": tool,
            "status": _sift_v4_status(payload),
            "record_count": _sift_v4_record_count(payload),
        }

        if _sift_v4_is_hit_payload(payload):
            hit[tool] = info
        else:
            zero.setdefault(tool, info)

    for tool in list(zero):
        if tool in hit:
            zero.pop(tool, None)

    return hit, zero


def _sift_v4_latest_state_dir() -> _SiftV4Path | None:
    for env_name in ("SIFT_STATE_DIR", "SIFT_SENTINEL_STATE_DIR", "SIFT_ACTIVE_STATE_DIR"):
        val = _sift_v4_os.environ.get(env_name)
        if val and _SiftV4Path(val).exists():
            return _SiftV4Path(val)

    roots = sorted(
        _SiftV4Path("/tmp").glob("sift-sentinel-run-*"),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )
    return roots[0] if roots else None


def _sift_v4_load_json(path: _SiftV4Path) -> _SiftV4Any:
    return _sift_v4_json.loads(path.read_text(errors="ignore"))


def _sift_v4_dump_json(path: _SiftV4Path, obj: _SiftV4Any) -> None:
    path.write_text(_sift_v4_json.dumps(obj, indent=2, sort_keys=False) + "\n")


def _sift_v4_load_outputs(state: _SiftV4Path) -> dict[str, _SiftV4Any]:
    outputs: dict[str, _SiftV4Any] = {}
    p = state / "all_outputs.json"
    if p.exists():
        try:
            obj = _sift_v4_load_json(p)
            if isinstance(obj, dict):
                outputs.update(obj)
        except Exception:
            pass

    td = state / "tool_outputs"
    if td.exists():
        for f in sorted(td.glob("*.json")):
            try:
                outputs[f.stem] = _sift_v4_load_json(f)
            except Exception:
                pass

    return outputs


def _sift_v4_state_json_files(state: _SiftV4Path) -> list[_SiftV4Path]:
    names = [
        "finding_disposition_buckets.json",
        "findings_final.json",
        "findings_validated.json",
        "pipeline_summary.json",
        "evidence_db.json",
    ]
    return [state / n for n in names if (state / n).exists()]


def _sift_v4_looks_like_tool(value: _SiftV4Any, hit: dict, zero: dict) -> bool:
    if not isinstance(value, str):
        return False
    c = canonical_tool_name(value)
    if not c:
        return False
    return (
        c in hit
        or c in zero
        or c.startswith(_SIFT_V4_TOOL_PREFIXES)
        or "appcompatcacheparser" in c
        or c in {"appcompatcache", "shimcache", "lecmd", "jlecmd", "srumecmd"}
    )


def _sift_v4_split_tool_string(value: str) -> list[str]:
    raw = value.strip()
    if "," in raw:
        return [x.strip() for x in raw.split(",") if x.strip()]
    return [raw]


def _sift_v4_normalize_tool_values(value: _SiftV4Any, hit: dict, zero: dict, stats: dict) -> _SiftV4Any:
    values = value if isinstance(value, list) else _sift_v4_split_tool_string(value) if isinstance(value, str) else [value]
    kept: list[str] = []

    for item in values:
        if not isinstance(item, str):
            continue

        c = canonical_tool_name(item)
        if c in hit:
            if c not in kept:
                kept.append(c)
            if c != item:
                stats["canonicalized_refs"] = stats.get("canonicalized_refs", 0) + 1
            continue

        if c in zero or _sift_v4_looks_like_tool(item, hit, zero):
            stats["removed_refs"] = stats.get("removed_refs", 0) + 1
            stats.setdefault("removed_tools", {}).setdefault(c or str(item), 0)
            stats["removed_tools"][c or str(item)] += 1
            continue

    if isinstance(value, list):
        return kept
    return kept[0] if kept else None


def _sift_v4_collect_refs(obj: _SiftV4Any, out: list[str], hit: dict | None = None, zero: dict | None = None) -> None:
    hit = hit or {}
    zero = zero or {}

    if isinstance(obj, dict):
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in _SIFT_V4_TOOL_REF_FIELDS:
                vals = v if isinstance(v, list) else _sift_v4_split_tool_string(v) if isinstance(v, str) else [v]
                for item in vals:
                    if isinstance(item, str) and _sift_v4_looks_like_tool(item, hit, zero):
                        out.append(canonical_tool_name(item))
                continue
            _sift_v4_collect_refs(v, out, hit, zero)
    elif isinstance(obj, list):
        for item in obj:
            _sift_v4_collect_refs(item, out, hit, zero)


def _sift_v4_sanitize_obj(obj: _SiftV4Any, hit: dict, zero: dict, stats: dict) -> _SiftV4Any:
    if isinstance(obj, list):
        return [_sift_v4_sanitize_obj(x, hit, zero, stats) for x in obj]

    if not isinstance(obj, dict):
        return obj

    # Claims are special: if a claim only cited zero/absent tools, drop that claim.
    claims = obj.get("claims")
    if isinstance(claims, list):
        new_claims = []
        for claim in claims:
            before: list[str] = []
            _sift_v4_collect_refs(claim, before, hit, zero)
            fixed = _sift_v4_sanitize_obj(claim, hit, zero, stats)
            after: list[str] = []
            _sift_v4_collect_refs(fixed, after, hit, zero)

            if before and not after:
                stats["dropped_claims"] = stats.get("dropped_claims", 0) + 1
                continue
            new_claims.append(fixed)
        obj["claims"] = new_claims

    for k in list(obj.keys()):
        lk = str(k).lower()
        if lk == "claims":
            continue

        if lk in _SIFT_V4_TOOL_REF_FIELDS:
            fixed_value = _sift_v4_normalize_tool_values(obj[k], hit, zero, stats)
            if fixed_value is None or fixed_value == []:
                obj.pop(k, None)
            else:
                obj[k] = fixed_value
            continue

        obj[k] = _sift_v4_sanitize_obj(obj[k], hit, zero, stats)

    return obj


def _sift_v4_finding_has_hit_ref(finding: dict, hit: dict, zero: dict) -> bool:
    refs: list[str] = []
    _sift_v4_collect_refs(finding, refs, hit, zero)
    return any(r in hit for r in refs)


def _sift_v4_repair_bucket_doc(doc: _SiftV4Any, hit: dict, zero: dict, stats: dict) -> _SiftV4Any:
    if not isinstance(doc, dict):
        return _sift_v4_sanitize_obj(doc, hit, zero, stats)

    root = doc.get("finding_disposition_buckets") if isinstance(doc.get("finding_disposition_buckets"), dict) else doc

    if not isinstance(root, dict) or not (_SIFT_V4_BUCKET_KEYS & set(root.keys())):
        return _sift_v4_sanitize_obj(doc, hit, zero, stats)

    inconclusive = list(root.get("inconclusive_unresolved") or [])

    for bucket_name in list(root.keys()):
        if bucket_name not in _SIFT_V4_BUCKET_KEYS:
            continue

        items = root.get(bucket_name)
        if not isinstance(items, list):
            continue

        new_items = []
        for item in items:
            if not isinstance(item, dict):
                new_items.append(item)
                continue

            before_refs: list[str] = []
            _sift_v4_collect_refs(item, before_refs, hit, zero)

            fixed = _sift_v4_sanitize_obj(item, hit, zero, stats)

            after_refs: list[str] = []
            _sift_v4_collect_refs(fixed, after_refs, hit, zero)

            if bucket_name in {"confirmed_malicious_atomic", "suspicious_needs_review", "synthesis_narrative"}:
                if before_refs and not any(r in hit for r in after_refs):
                    fixed["tool_hit_integrity_status"] = "inconclusive_no_data_producing_hit_tool"
                    fixed["tool_hit_integrity_reason"] = "finding lost all data-producing tool support after zero/non-hit tool cleanup"
                    inconclusive.append(fixed)
                    stats["routed_nohit_to_inconclusive"] = stats.get("routed_nohit_to_inconclusive", 0) + 1
                    continue

            new_items.append(fixed)

        root[bucket_name] = new_items

    root["inconclusive_unresolved"] = inconclusive
    return doc


def _sift_v4_scan_bad_refs(obj: _SiftV4Any, hit: dict, zero: dict, path: str = "$") -> list[dict]:
    bad: list[dict] = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in _SIFT_V4_TOOL_REF_FIELDS:
                vals = v if isinstance(v, list) else _sift_v4_split_tool_string(v) if isinstance(v, str) else [v]
                for item in vals:
                    if not isinstance(item, str) or not _sift_v4_looks_like_tool(item, hit, zero):
                        continue
                    c = canonical_tool_name(item)
                    if c in zero:
                        bad.append({"path": f"{path}.{k}", "tool": c, "kind": "zero_or_nonhit"})
                    elif c not in hit:
                        bad.append({"path": f"{path}.{k}", "tool": c, "kind": "absent"})
                continue
            bad.extend(_sift_v4_scan_bad_refs(v, hit, zero, f"{path}.{k}"))

    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            bad.extend(_sift_v4_scan_bad_refs(item, hit, zero, f"{path}[{i}]"))

    return bad


def enforce_state_tool_hit_integrity(
    state_dir: str | _SiftV4Path | None = None,
    *,
    repair: bool = False,
    fail: bool = False,
) -> dict:
    state = _SiftV4Path(state_dir) if state_dir else _sift_v4_latest_state_dir()
    if state is None or not state.exists():
        result = {"status": "no_state", "removed_refs": 0, "bad_refs": []}
        if fail:
            raise RuntimeError("no SIFT state directory found for tool-hit integrity gate")
        return result

    outputs = _sift_v4_load_outputs(state)
    hit, zero = build_hit_maps(outputs)

    stats: dict = {
        "state": str(state),
        "hit_tools": sorted(hit),
        "zero_or_nonhit_tools": sorted(zero),
        "removed_refs": 0,
        "canonicalized_refs": 0,
        "dropped_claims": 0,
        "routed_nohit_to_inconclusive": 0,
    }

    files = _sift_v4_state_json_files(state)

    if repair:
        for f in files:
            try:
                obj = _sift_v4_load_json(f)
                before = _sift_v4_json.dumps(obj, sort_keys=True, default=str)
                fixed = _sift_v4_repair_bucket_doc(obj, hit, zero, stats)
                after = _sift_v4_json.dumps(fixed, sort_keys=True, default=str)
                if before != after:
                    _sift_v4_dump_json(f, fixed)
                    stats.setdefault("repaired_files", []).append(str(f))
            except Exception as exc:
                stats.setdefault("repair_errors", []).append({"file": str(f), "error": str(exc)})

    bad_refs: list[dict] = []
    for f in files:
        try:
            obj = _sift_v4_load_json(f)
            for item in _sift_v4_scan_bad_refs(obj, hit, zero, str(f.name)):
                bad_refs.append(item)
        except Exception as exc:
            bad_refs.append({"path": str(f), "tool": "", "kind": "scan_error", "error": str(exc)})

    stats["bad_refs"] = bad_refs
    stats["status"] = "pass" if not bad_refs else "fail"

    if bad_refs and fail:
        sample = bad_refs[:20]
        raise RuntimeError(f"tool-hit integrity violations remain: {sample}")

    return stats


def enforce_latest_state_tool_hit_integrity(
    *,
    repair: bool = False,
    fail: bool = False,
    state_dir: str | _SiftV4Path | None = None,
) -> dict:
    # SIFT_LATEST_STATE_RESOLVE_V1
    if state_dir is None:
        import os, glob
        env_sd = os.environ.get("SIFT_STATE_DIR") or os.environ.get("SIFT_RUN_STATE_DIR")
        if env_sd:
            state_dir = env_sd
        else:
            _runs = sorted(
                glob.glob("/tmp/sift-sentinel-run-*"),
                key=lambda p: os.path.getmtime(p),
                reverse=True,
            )
            if not _runs:
                raise RuntimeError(
                    "enforce_latest_state_tool_hit_integrity: no state_dir given and "
                    "no /tmp/sift-sentinel-run-* directory found to resolve as latest"
                )
            state_dir = _runs[0]
    return enforce_state_tool_hit_integrity(state_dir=state_dir, repair=repair, fail=fail)

# SIFT_TOOL_HIT_INTEGRITY_DELEGATES_TO_PROVENANCE_TAXONOMY_V1
# Keep the historical public function name, but route enforcement through the
# universal taxonomy so rules/backends are not treated as tools and zero-record
# tools cannot support findings.
try:
    from sift_sentinel.analysis.provenance_taxonomy import (
        enforce_state_tool_hit_integrity as _sift_taxonomy_enforce_state_tool_hit_integrity_v1,
    )

    def enforce_state_tool_hit_integrity(state_dir, repair=False, route_nohit=True, **kwargs):
        return _sift_taxonomy_enforce_state_tool_hit_integrity_v1(
            state_dir,
            repair=repair,
            route_nohit=route_nohit,
            **kwargs,
        )
except Exception:
    pass

# SIFT_TOOL_HIT_REPAIR_AUDIT_SANITIZER_V5
#
# Final findings must not retain zero/non-hit tool names inside per-finding
# audit metadata. Active provenance fields are repaired by the canonical
# enforcement function. This wrapper additionally moves detailed removed-ref
# audit trails to a state-level sidecar and leaves only numeric counts in each
# finding object. This is dataset-agnostic and uses current-run state only.

from pathlib import Path as _SiftThPathV5
import json as _sift_th_json_v5
from typing import Any as _SiftThAnyV5


_SIFT_TH_AUDIT_KEYS_V5 = {
    "removed_tool_refs",
    "stripped_tool_refs",
    "bad_tool_refs",
    "invalid_tool_refs",
    "zero_tool_refs",
    "zero_or_nonhit_tool_refs",
    "nonproducer_tool_refs",
    "absent_tool_refs",
    "tool_hit_integrity_removed_refs",
    "provenance_removed_refs",
    "provenance_taxonomy_removed_refs",
    "_removed_tool_refs",
}


def _sift_th_load_json_v5(path: _SiftThPathV5, default: _SiftThAnyV5) -> _SiftThAnyV5:
    try:
        return _sift_th_json_v5.loads(path.read_text(errors="ignore"))
    except Exception:
        return default


def _sift_th_write_json_v5(path: _SiftThPathV5, data: _SiftThAnyV5) -> None:
    path.write_text(_sift_th_json_v5.dumps(data, indent=2, sort_keys=True))


def _sift_th_finding_id_v5(finding: dict[str, _SiftThAnyV5], fallback: str = "") -> str:
    for key in ("id", "finding_id", "uid", "uuid"):
        val = finding.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return fallback


def _sift_th_scrub_audit_keys_v5(
    obj: _SiftThAnyV5,
    *,
    finding_id: str,
    audit_rows: list[dict[str, _SiftThAnyV5]],
) -> tuple[_SiftThAnyV5, int]:
    removed_count = 0

    if isinstance(obj, dict):
        out: dict[str, _SiftThAnyV5] = {}
        for key, value in obj.items():
            key_s = str(key)
            key_l = key_s.lower()

            is_audit_key = (
                key_s in _SIFT_TH_AUDIT_KEYS_V5
                or (("removed" in key_l or "stripped" in key_l or "invalid" in key_l or "absent" in key_l)
                    and ("tool" in key_l or "provenance" in key_l)
                    and key_s not in {"source_tools", "claim_tools", "tools_hit"})
            )

            if is_audit_key:
                # Move detailed audit to sidecar; do not keep raw tool names in final finding.
                if isinstance(value, list):
                    removed_count += len(value)
                elif value:
                    removed_count += 1
                audit_rows.append({
                    "finding_id": finding_id,
                    "audit_key": key_s,
                    "value": value,
                })
                continue

            cleaned, n = _sift_th_scrub_audit_keys_v5(
                value, finding_id=finding_id, audit_rows=audit_rows
            )
            removed_count += n
            out[key] = cleaned

        return out, removed_count

    if isinstance(obj, list):
        cleaned_list = []
        for value in obj:
            cleaned, n = _sift_th_scrub_audit_keys_v5(
                value, finding_id=finding_id, audit_rows=audit_rows
            )
            removed_count += n
            cleaned_list.append(cleaned)
        return cleaned_list, removed_count

    return obj, 0


def _sift_th_sanitize_findings_file_v5(path: _SiftThPathV5, audit_rows: list[dict[str, _SiftThAnyV5]]) -> int:
    data = _sift_th_load_json_v5(path, None)
    if data is None:
        return 0

    changed_count = 0

    def sanitize_one(f: dict[str, _SiftThAnyV5], fallback: str = "") -> dict[str, _SiftThAnyV5]:
        nonlocal changed_count
        fid = _sift_th_finding_id_v5(f, fallback)
        before_audit_len = len(audit_rows)
        cleaned, removed_n = _sift_th_scrub_audit_keys_v5(f, finding_id=fid, audit_rows=audit_rows)
        if isinstance(cleaned, dict) and removed_n:
            cleaned["provenance_repair_audit_ref"] = "tool_hit_integrity_repair_audit.json"
            cleaned["provenance_repair_removed_ref_count"] = (
                int(cleaned.get("provenance_repair_removed_ref_count") or 0) + removed_n
            )
            changed_count += 1
        elif len(audit_rows) != before_audit_len:
            changed_count += 1
        return cleaned if isinstance(cleaned, dict) else f

    if isinstance(data, list):
        new_data = [
            sanitize_one(x, str(i))
            if isinstance(x, dict)
            else x
            for i, x in enumerate(data)
        ]
    elif isinstance(data, dict):
        new_data = {}
        for key, value in data.items():
            if isinstance(value, list):
                new_data[key] = [
                    sanitize_one(x, f"{key}:{i}")
                    if isinstance(x, dict)
                    else x
                    for i, x in enumerate(value)
                ]
            elif isinstance(value, dict) and ("claims" in value or "source_tools" in value or "tools_hit" in value):
                new_data[key] = sanitize_one(value, str(key))
            else:
                new_data[key] = value
    else:
        return 0

    if changed_count:
        _sift_th_write_json_v5(path, new_data)
    return changed_count


def sanitize_tool_hit_repair_audit_from_state(
    state_dir: str | _SiftThPathV5,
) -> dict[str, _SiftThAnyV5]:
    state = _SiftThPathV5(state_dir)
    audit_rows: list[dict[str, _SiftThAnyV5]] = []
    files = [
        state / "finding_disposition_buckets.json",
        state / "findings_final.json",
        state / "findings_validated.json",
        state / "findings.json",
    ]

    changed_files = 0
    changed_findings = 0
    for path in files:
        if not path.exists():
            continue
        n = _sift_th_sanitize_findings_file_v5(path, audit_rows)
        if n:
            changed_files += 1
            changed_findings += n

    if audit_rows:
        audit_path = state / "tool_hit_integrity_repair_audit.json"
        prior = _sift_th_load_json_v5(audit_path, [])
        if not isinstance(prior, list):
            prior = []
        prior.extend(audit_rows)
        _sift_th_write_json_v5(audit_path, prior)

    return {
        "changed_files": changed_files,
        "changed_findings": changed_findings,
        "audit_rows_moved": len(audit_rows),
    }


# Wrap the currently active enforcement function without reimplementing policy.
_sift_th_original_enforce_state_tool_hit_integrity_v5 = enforce_state_tool_hit_integrity


def enforce_state_tool_hit_integrity(*args, **kwargs):
    result = _sift_th_original_enforce_state_tool_hit_integrity_v5(*args, **kwargs)

    # Locate state_dir robustly from positional or keyword arguments.
    state_dir = kwargs.get("state_dir")
    if state_dir is None and args:
        state_dir = args[0]

    repair_requested = bool(kwargs.get("repair", False))
    if not repair_requested:
        # Some callers use positional repair as second arg.
        if len(args) >= 2 and isinstance(args[1], bool):
            repair_requested = bool(args[1])

    if state_dir and repair_requested:
        try:
            audit = sanitize_tool_hit_repair_audit_from_state(state_dir)
            if isinstance(result, dict):
                result["audit_metadata_sanitized"] = audit
        except Exception as exc:
            if isinstance(result, dict):
                result["audit_metadata_sanitizer_error"] = f"{type(exc).__name__}: {exc}"

    return result


# SIFT_TOOL_HIT_ACTIVE_STATE_RESOLVER_V1
# Final wrapper: pre-report gates must resolve an active state dir and must never
# call Path(None) through lower-level provenance code.
try:
    _sift_th_prior_enforce_state_tool_hit_integrity_v1 = enforce_state_tool_hit_integrity
except NameError:  # pragma: no cover
    _sift_th_prior_enforce_state_tool_hit_integrity_v1 = None

try:
    _sift_th_prior_enforce_latest_state_tool_hit_integrity_v1 = enforce_latest_state_tool_hit_integrity
except NameError:  # pragma: no cover
    _sift_th_prior_enforce_latest_state_tool_hit_integrity_v1 = None


def _sift_th_resolve_state_v1(value=None):
    from sift_sentinel.analysis.state_dir_resolver import resolve_state_dir
    resolved = resolve_state_dir(value, require_existing=True, require_marker=False)
    return resolved


def enforce_state_tool_hit_integrity(*args, **kwargs):
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

    resolved = _sift_th_resolve_state_v1(state_dir)
    if not resolved:
        result = {
            "status": "fail",
            "reason": "active_state_dir_not_resolved",
            "bad_refs": 1,
            "removed_refs": 0,
            "canonicalized_refs": 0,
            "dropped_claims": 0,
            "routed_nohit_to_inconclusive": 0,
        }
        if kwargs.get("fail"):
            raise RuntimeError("TOOL_HIT_INTEGRITY_GATE=FAIL reason=active_state_dir_not_resolved")
        return result

    kwargs["state_dir"] = resolved
    if _sift_th_prior_enforce_state_tool_hit_integrity_v1 is None:
        return {"status": "pass", "state_dir": resolved}

    return _sift_th_prior_enforce_state_tool_hit_integrity_v1(*args_list, **kwargs)


def enforce_latest_state_tool_hit_integrity(*args, **kwargs):
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

    resolved = _sift_th_resolve_state_v1(state_dir)
    if not resolved:
        result = {
            "status": "fail",
            "reason": "active_state_dir_not_resolved",
            "bad_refs": 1,
            "removed_refs": 0,
            "canonicalized_refs": 0,
            "dropped_claims": 0,
            "routed_nohit_to_inconclusive": 0,
        }
        if kwargs.get("fail"):
            raise RuntimeError("TOOL_HIT_INTEGRITY_GATE=FAIL reason=active_state_dir_not_resolved")
        return result

    kwargs["state_dir"] = resolved
    return enforce_state_tool_hit_integrity(*args_list, **kwargs)

