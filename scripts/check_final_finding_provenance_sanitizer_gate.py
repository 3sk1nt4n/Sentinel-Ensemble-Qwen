#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

BAD_PUBLIC_PROVENANCE_TOKENS = {
    "typed_evidence_db",
    "reference_set",
    "check_ancestry",
}

NON_TOOL_SOURCE_TOKENS = BAD_PUBLIC_PROVENANCE_TOKENS | {
    "evidence_db",
    "validator",
    "validation_engine",
    "report_validation",
    "react",
    "self_correction",
    "confidence",
    "reconciliation",
    "candidate_observations",
}

SOURCEISH_KEYS = {
    "source_tool",
    "source_tools",
    "claim_tool",
    "claim_tools",
    "tools_hit",
    "tool",
    "tools",
    "producer",
    "producers",
    "producing_tool",
    "producing_tools",
}

PUBLIC_FINAL_ARTIFACTS = (
    "finding_disposition_buckets.json",
    "findings_final.json",
    "findings_validated.json",
)

ALIASES = {
    "tool_parse_appcompatcacheparser": "run_appcompatcacheparser",
    "parse_appcompatcacheparser": "run_appcompatcacheparser",
    "tool_run_appcompatcacheparser": "run_appcompatcacheparser",
    "tool_vol_svescan": "vol_svcscan",
    "vol_svescan": "vol_svcscan",
}


def _load_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(errors="replace"))
    except Exception:
        return default
    return default


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def _canon_tool(value: Any) -> str:
    text = str(value or "").strip()
    if text.startswith("tool_"):
        text = text[5:]
    return ALIASES.get(text, text)


def _lower(value: Any) -> str:
    return str(value or "").lower()


def _contains_bad_token(value: Any) -> bool:
    text = _lower(value)
    return any(token in text for token in BAD_PUBLIC_PROVENANCE_TOKENS)


def _is_bad_source_value(value: Any) -> bool:
    raw = _lower(value)
    canon = _canon_tool(value).lower()
    if not canon:
        return True
    if raw in NON_TOOL_SOURCE_TOKENS or canon in NON_TOOL_SOURCE_TOKENS:
        return True
    if any(token in raw for token in BAD_PUBLIC_PROVENANCE_TOKENS):
        return True
    return False


def _scan_bad_paths(obj: Any, path: str = "$") -> list[str]:
    hits: list[str] = []

    if isinstance(obj, dict):
        for key, value in obj.items():
            key_s = str(key)
            child = f"{path}.{key_s}"
            if _contains_bad_token(key_s):
                hits.append(child + " <bad-key>")
            hits.extend(_scan_bad_paths(value, child))
        return hits

    if isinstance(obj, list):
        for idx, value in enumerate(obj):
            hits.extend(_scan_bad_paths(value, f"{path}[{idx}]"))
        return hits

    if isinstance(obj, str) and _contains_bad_token(obj):
        hits.append(path + " <bad-string>")

    return hits


def _sanitize_sourceish_value(key: str, value: Any, audit: list[dict[str, Any]], path: str) -> Any:
    if isinstance(value, list):
        out = []
        seen = set()
        for item in value:
            if _is_bad_source_value(item):
                audit.append({"path": path, "field": key, "removed": item, "reason": "internal_or_non_tool_source"})
                continue
            canon = _canon_tool(item)
            if canon not in seen:
                out.append(canon)
                seen.add(canon)
        return out

    if isinstance(value, str):
        if _is_bad_source_value(value):
            audit.append({"path": path, "field": key, "removed": value, "reason": "internal_or_non_tool_source"})
            return None
        return _canon_tool(value)

    return value


def _sanitize(obj: Any, audit: list[dict[str, Any]], path: str = "$") -> Any:
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            key_s = str(key)
            key_l = key_s.lower()
            child = f"{path}.{key_s}"

            if _contains_bad_token(key_s) or key_l in {
                "_validation_telemetry",
                "validation_telemetry",
                "validator_telemetry",
                "provenance_audit",
                "_provenance_audit",
            }:
                audit.append({"path": child, "field": key_s, "removed": value, "reason": "internal_field"})
                continue

            if key_l in SOURCEISH_KEYS:
                cleaned = _sanitize_sourceish_value(key_l, value, audit, child)
                if cleaned is None:
                    continue
                out[key] = cleaned
                continue

            cleaned = _sanitize(value, audit, child)
            if cleaned is None:
                audit.append({"path": child, "field": key_s, "removed": value, "reason": "bad_public_token_value"})
                continue
            out[key] = cleaned
        return out

    if isinstance(obj, list):
        out = []
        for idx, value in enumerate(obj):
            cleaned = _sanitize(value, audit, f"{path}[{idx}]")
            if cleaned is not None:
                out.append(cleaned)
        return out

    if isinstance(obj, str) and _contains_bad_token(obj):
        audit.append({"path": path, "removed": obj, "reason": "bad_public_token_string"})
        return None

    return obj


def _artifact_violations(state: Path) -> list[str]:
    violations: list[str] = []
    for name in PUBLIC_FINAL_ARTIFACTS:
        path = state / name
        if not path.exists():
            continue
        data = _load_json(path, None)
        if data is None:
            continue
        for bad_path in _scan_bad_paths(data, f"${name}"):
            violations.append(bad_path)
    return violations


def _repair_state(state: Path) -> tuple[int, int]:
    all_audit: list[dict[str, Any]] = []
    changed_files = 0

    for name in PUBLIC_FINAL_ARTIFACTS:
        path = state / name
        if not path.exists():
            continue

        original = _load_json(path, None)
        if original is None:
            continue

        audit: list[dict[str, Any]] = []
        cleaned = _sanitize(original, audit, f"${name}")

        if cleaned != original:
            _write_json(path, cleaned)
            changed_files += 1

        all_audit.extend(audit)

    if all_audit:
        audit_path = state / "final_finding_provenance_sanitizer_audit.json"
        previous = _load_json(audit_path, [])
        if not isinstance(previous, list):
            previous = []
        previous.extend(all_audit)
        _write_json(audit_path, previous)

    return changed_files, len(all_audit)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("state_dir", nargs="?")
    ap.add_argument("--repair", action="store_true")
    args = ap.parse_args()

    if not args.state_dir:
        print("FINAL_FINDING_PROVENANCE_SANITIZER_GATE=FAIL reason=no_state")
        return 2

    state = Path(args.state_dir)
    if not state.exists():
        print(f"FINAL_FINDING_PROVENANCE_SANITIZER_GATE=FAIL reason=missing_state state={state}")
        return 2

    before = _artifact_violations(state)
    changed_files = 0
    audit_rows = 0

    if args.repair and before:
        changed_files, audit_rows = _repair_state(state)

    after = _artifact_violations(state)

    if args.repair:
        status = "pass" if not after else "fail"
        print(
            "FINAL_FINDING_PROVENANCE_SANITIZER_REPAIR "
            f"status={status} changed_files={changed_files} audit_rows={audit_rows} "
            f"before={len(before)} after={len(after)}"
        )

    if after:
        print(
            f"FINAL_FINDING_PROVENANCE_SANITIZER_GATE=FAIL "
            f"state={state} violations={len(after)}"
        )
        for item in after[:80]:
            print(item)
        return 1

    print(f"FINAL_FINDING_PROVENANCE_SANITIZER_GATE=PASS state={state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
