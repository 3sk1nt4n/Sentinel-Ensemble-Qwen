from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# SIFT_FINAL_FINDING_PROVENANCE_SANITIZER_V6
#
# Dataset-agnostic rule:
#   Final finding JSONs may cite only real data-producing forensic tools.
#   Zero/non-hit/absent tools and internal validation engines are moved out of
#   finding objects into a state-level audit sidecar.

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

FINDING_FILES = (
    "finding_disposition_buckets.json",
    "findings_final.json",
    "findings_validated.json",
    "findings.json",
)

AUDIT_SIDECAR = "final_finding_provenance_sanitization_audit.json"

PROVENANCE_FIELDS = {
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

AUDITISH_KEY_PARTS = (
    "audit",
    "removed",
    "stripped",
    "invalid",
    "bad",
    "zero",
    "nonhit",
    "non_hit",
    "nonproducer",
    "absent",
    "repair",
    "debug",
)

# These are not forensic tools. They are validation engines/rules/metadata.
# They must never appear as hit tools or final customer finding provenance.
NON_TOOL_PROVENANCE_REFS = {
    "check_ancestry",
    "typed_evidence_db",
    "typed_validator",
    "reference_set",
    "self_correction",
    "react_cross_check",
    "provenance_taxonomy",
    "tool_hit_integrity",
}


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(errors="ignore"))
    except Exception:
        return default


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True))


def canonical_tool(raw: Any) -> str:
    s = str(raw or "").strip()
    if not s:
        return ""
    if s.startswith("tool_"):
        s = s[5:]

    # Universal alias cleanup; not dataset-specific.
    aliases = {
        "parse_appcompatcacheparser": "run_appcompatcacheparser",
        "tool_parse_appcompatcacheparser": "run_appcompatcacheparser",
        "vol_svescan": "vol_svcscan",
        "tool_vol_svescan": "vol_svcscan",
    }
    return aliases.get(s, s)


def record_count(obj: Any) -> int:
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


def status_of(obj: Any) -> str:
    if isinstance(obj, dict):
        for key in ("status", "result_status", "tool_status"):
            val = obj.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip().lower()
    return "ok" if record_count(obj) > 0 else "no_records"


def output_manifest(state_dir: str | Path) -> dict[str, Any]:
    state = Path(state_dir)
    all_outputs = load_json(state / "all_outputs.json", {})
    tools: dict[str, dict[str, Any]] = {}

    if isinstance(all_outputs, dict):
        for raw_name, obj in all_outputs.items():
            name = canonical_tool(raw_name)
            if not name:
                continue
            tools[name] = {
                "records": record_count(obj),
                "status": status_of(obj),
            }

    tool_outputs = state / "tool_outputs"
    if tool_outputs.is_dir():
        for path in tool_outputs.glob("*.json"):
            name = canonical_tool(path.stem)
            obj = load_json(path, {})
            prev = tools.get(name)
            recs = record_count(obj)
            status = status_of(obj)
            if prev is None or recs > int(prev.get("records") or 0):
                tools[name] = {"records": recs, "status": status}

    producer_tools = set()
    nonproducer_tools = set()

    for name, meta in tools.items():
        recs = int(meta.get("records") or 0)
        status = str(meta.get("status") or "").lower()
        if recs > 0 and status not in BAD_STATUSES:
            producer_tools.add(name)
        else:
            nonproducer_tools.add(name)

    # If a tool somehow appears in both, production wins only if it has records.
    nonproducer_tools -= producer_tools

    disallowed = set(nonproducer_tools)
    disallowed.update(f"tool_{x}" for x in nonproducer_tools)
    disallowed.update(NON_TOOL_PROVENANCE_REFS)

    return {
        "tools": tools,
        "producer_tools": sorted(producer_tools),
        "nonproducer_tools": sorted(nonproducer_tools),
        "disallowed_refs": sorted(x for x in disallowed if x),
    }


def finding_id(obj: Any, fallback: str = "") -> str:
    if isinstance(obj, dict):
        for key in ("id", "finding_id", "uid", "uuid"):
            val = obj.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return fallback


def contains_disallowed(value: Any, disallowed: set[str]) -> bool:
    text = json.dumps(value, sort_keys=True) if not isinstance(value, str) else value
    for token in disallowed:
        if token and token in text:
            return True
    return False


def scrub_string(text: str, disallowed: set[str], audit_rows: list[dict[str, Any]], *, fid: str, path: str) -> str:
    out = text
    for token in sorted(disallowed, key=len, reverse=True):
        if not token:
            continue
        if token not in out:
            continue
        replacement = "[validation-metadata]" if token in NON_TOOL_PROVENANCE_REFS else "[non-producing-tool]"
        new = re.sub(rf"(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])", replacement, out)
        if new != out:
            audit_rows.append({
                "finding_id": fid,
                "path": path,
                "action": "string_token_replaced",
                "token_class": "non_tool" if token in NON_TOOL_PROVENANCE_REFS else "zero_or_nonhit_tool",
                "token": token,
            })
            out = new
    return out


def scrub_obj(
    obj: Any,
    *,
    disallowed: set[str],
    producer_tools: set[str],
    audit_rows: list[dict[str, Any]],
    fid: str,
    path: str = "",
) -> tuple[Any, int]:
    changes = 0

    if isinstance(obj, str):
        new = scrub_string(obj, disallowed, audit_rows, fid=fid, path=path)
        return new, int(new != obj)

    if isinstance(obj, list):
        # Tool provenance lists: keep only producers, canonicalized.
        base_key = path.rsplit(".", 1)[-1]
        if base_key in {"source_tools", "claim_tools", "tools_hit", "producer_tools"}:
            new_list = []
            for val in obj:
                c = canonical_tool(val)
                if c in producer_tools:
                    if c not in new_list:
                        new_list.append(c)
                else:
                    if str(val or "").strip():
                        audit_rows.append({
                            "finding_id": fid,
                            "path": path,
                            "action": "tool_list_ref_removed",
                            "raw": val,
                            "canonical": c,
                        })
                        changes += 1
            return new_list, changes

        new_items = []
        for i, val in enumerate(obj):
            # Drop claims whose only cited source tool is non-producing/non-tool.
            if isinstance(val, dict) and path.endswith("claims"):
                st = val.get("source_tool") or val.get("tool") or val.get("claim_tool")
                stc = canonical_tool(st)
                if st and stc not in producer_tools:
                    audit_rows.append({
                        "finding_id": fid,
                        "path": f"{path}[{i}]",
                        "action": "claim_dropped_nonproducer_source",
                        "raw": st,
                        "canonical": stc,
                    })
                    changes += 1
                    continue

            cleaned, n = scrub_obj(
                val,
                disallowed=disallowed,
                producer_tools=producer_tools,
                audit_rows=audit_rows,
                fid=fid,
                path=f"{path}[{i}]",
            )
            changes += n
            new_items.append(cleaned)
        return new_items, changes

    if isinstance(obj, dict):
        new_dict: dict[str, Any] = {}

        for key, val in obj.items():
            key_s = str(key)
            key_l = key_s.lower()
            child_path = f"{path}.{key_s}" if path else key_s

            if any(part in key_l for part in AUDITISH_KEY_PARTS) and contains_disallowed(val, disallowed):
                audit_rows.append({
                    "finding_id": fid,
                    "path": child_path,
                    "action": "auditish_field_moved_to_sidecar",
                    "key": key_s,
                    "value": val,
                })
                changes += 1
                continue

            if key_s in PROVENANCE_FIELDS:
                if isinstance(val, list):
                    cleaned, n = scrub_obj(
                        val,
                        disallowed=disallowed,
                        producer_tools=producer_tools,
                        audit_rows=audit_rows,
                        fid=fid,
                        path=child_path,
                    )
                    changes += n
                    if cleaned or key_s not in {"source_tools", "claim_tools", "tools_hit"}:
                        new_dict[key_s] = cleaned
                    continue

                c = canonical_tool(val)
                if c in producer_tools:
                    new_dict[key_s] = c
                else:
                    if str(val or "").strip():
                        audit_rows.append({
                            "finding_id": fid,
                            "path": child_path,
                            "action": "single_tool_ref_removed",
                            "raw": val,
                            "canonical": c,
                        })
                        changes += 1
                    continue

            cleaned, n = scrub_obj(
                val,
                disallowed=disallowed,
                producer_tools=producer_tools,
                audit_rows=audit_rows,
                fid=fid,
                path=child_path,
            )
            changes += n
            new_dict[key_s] = cleaned

        if changes:
            new_dict["provenance_sanitized"] = True
            new_dict["provenance_sanitization_audit_ref"] = AUDIT_SIDECAR

        return new_dict, changes

    return obj, 0


def sanitize_file(path: Path, manifest: dict[str, Any], audit_rows: list[dict[str, Any]]) -> int:
    data = load_json(path, None)
    if data is None:
        return 0

    disallowed = set(manifest["disallowed_refs"])
    producer_tools = set(manifest["producer_tools"])

    changes = 0

    def sanitize_finding(f: dict[str, Any], fallback: str) -> dict[str, Any]:
        nonlocal changes
        fid = finding_id(f, fallback)
        cleaned, n = scrub_obj(
            f,
            disallowed=disallowed,
            producer_tools=producer_tools,
            audit_rows=audit_rows,
            fid=fid,
        )
        changes += n
        return cleaned if isinstance(cleaned, dict) else f

    if isinstance(data, list):
        new_data = [
            sanitize_finding(x, str(i)) if isinstance(x, dict) else x
            for i, x in enumerate(data)
        ]
    elif isinstance(data, dict):
        new_data = {}
        for key, val in data.items():
            if isinstance(val, list):
                new_data[key] = [
                    sanitize_finding(x, f"{key}:{i}") if isinstance(x, dict) else x
                    for i, x in enumerate(val)
                ]
            elif isinstance(val, dict) and ("claims" in val or "source_tools" in val or "tools_hit" in val):
                new_data[key] = sanitize_finding(val, str(key))
            else:
                new_data[key] = val
    else:
        return 0

    if changes:
        write_json(path, new_data)

    return changes


def scan_finding_files(state_dir: str | Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    state = Path(state_dir)
    disallowed = set(manifest["disallowed_refs"])
    hits: list[dict[str, Any]] = []

    for name in FINDING_FILES:
        path = state / name
        if not path.exists():
            continue
        text = path.read_text(errors="ignore")
        for token in sorted(disallowed):
            if token and token in text:
                hits.append({"file": name, "token": token})
    return hits


def sanitize_state(state_dir: str | Path, *, repair: bool = False) -> dict[str, Any]:
    state = Path(state_dir)
    manifest = output_manifest(state)
    audit_rows: list[dict[str, Any]] = []
    changed_files = 0
    changed_refs = 0

    if repair:
        for name in FINDING_FILES:
            path = state / name
            if not path.exists():
                continue
            n = sanitize_file(path, manifest, audit_rows)
            if n:
                changed_files += 1
                changed_refs += n

        if audit_rows:
            audit_path = state / AUDIT_SIDECAR
            prior = load_json(audit_path, [])
            if not isinstance(prior, list):
                prior = []
            prior.extend(audit_rows)
            write_json(audit_path, prior)

    violations = scan_finding_files(state, manifest)
    return {
        "status": "pass" if not violations else "fail",
        "changed_files": changed_files,
        "changed_refs": changed_refs,
        "audit_rows_moved": len(audit_rows),
        "producer_tools": manifest["producer_tools"],
        "nonproducer_tools": manifest["nonproducer_tools"],
        "violations": violations,
    }
