#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from sift_sentinel.analysis.evidencedb_family_index import index_evidencedb_families
from sift_sentinel.analysis.validation_family_registry import get_validation_family_registry

# SIFT_VALIDATION_FAMILY_WIRING_GATE_ACTUAL_FAMILIES_V1F
#
# Gate contract:
# - Uses registry producer_tools as the source of truth.
# - Canonicalizes legacy family names to actual EvidenceDB family names.
# - Allows tools with DB-producing families but no registered target to pass as
#   PASS_DB_FAMILY_PRESENT_NO_REGISTERED_TARGET, because not every context tool
#   is finding-capable.
# - Fails when a registered finding/trigger tool produces records but no typed
#   EvidenceDB family is wired.
# - Fails when a registered target emits unregistered families.
# - Does not require optional attribution families to be present for every tool.

FAMILY_ALIASES = {
    "malfind_fact": "memory_injection_fact",
    "connection_fact": "network_connection_fact",
}

EXTRA_EXPECTED_BY_TOOL = {
    "vol_malfind": {"memory_injection_fact"},
    "vol_netscan": {"network_connection_fact"},
    "vol_pstree": {"process_fact", "process_relationship_fact"},
    "vol_psscan": {"process_fact", "process_relationship_fact"},
    "vol_cmdline": {"process_cmdline_fact", "user_account_fact"},
    "vol_handles": {"handle_fact", "user_account_fact"},
    "vol_getsids": {"sid_fact", "user_account_fact"},
    "vol_sessions": {"session_fact", "user_account_fact"},
}

STRICT_ROLES = {
    "finding_capable",
    "triggered_finding_capable",
}


def _canonical_family(fam: str) -> str:
    return FAMILY_ALIASES.get(str(fam or "").strip(), str(fam or "").strip())


def _load_json(path: Path) -> Any:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(errors="replace"))
    except Exception:
        return {}


def _count_records(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in ("records", "data", "rows", "items", "facts"):
            if isinstance(value.get(key), list):
                return len(value[key])
        if value.get("record_count") is not None:
            try:
                return int(value.get("record_count") or 0)
            except Exception:
                pass
        # A wrapper dict with status/reason and no rows is not a produced record.
        if any(k in value for k in ("status", "reason", "error")):
            return 0
        return 1
    return 1


def _normalize_tool_name(name: str) -> str:
    s = str(name or "").strip()
    if s.startswith("tool_"):
        s = s[5:]
    return s


def _selected_tools_from_log(log_path: Path | None) -> set[str]:
    if not log_path or not log_path.exists():
        return set()
    tools: set[str] = set()
    for line in log_path.read_text(errors="replace").splitlines():
        if "SELECTED:" in line:
            tools.add(_normalize_tool_name(line.rsplit("SELECTED:", 1)[-1].strip()))
        if "COLLECTED:" in line and "--" in line:
            part = line.split("COLLECTED:", 1)[-1].split("--", 1)[0].strip()
            tools.add(_normalize_tool_name(part))
        if "ZERO_RECORD_TOOL_RESULT tool=" in line:
            part = line.split("ZERO_RECORD_TOOL_RESULT tool=", 1)[-1].split()[0]
            tools.add(_normalize_tool_name(part))
    return {t for t in tools if t}


def _zero_reason_map(state: Path) -> dict[str, dict[str, Any]]:
    raw = _load_json(state / "zero_record_reasons.json")
    out: dict[str, dict[str, Any]] = {}

    if isinstance(raw, dict):
        for key, value in raw.items():
            if key == "zero_record_tools" and isinstance(value, list):
                for rec in value:
                    if isinstance(rec, dict) and rec.get("tool"):
                        out[_normalize_tool_name(str(rec["tool"]))] = rec
            elif isinstance(value, dict):
                out[_normalize_tool_name(str(key))] = value

    return out


def _registry_by_tool() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    reg = get_validation_family_registry()
    expected: dict[str, set[str]] = defaultdict(set)
    roles: dict[str, set[str]] = defaultdict(set)

    for family, spec in (reg or {}).items():
        if not isinstance(spec, dict):
            continue
        fam = _canonical_family(str(spec.get("family") or family))
        producer_tools = spec.get("producer_tools") or []
        if isinstance(producer_tools, str):
            producer_tools = [producer_tools]

        spec_roles: set[str] = set()
        role = spec.get("role")
        if role:
            spec_roles.add(str(role))
        rs = spec.get("roles") or []
        if isinstance(rs, str):
            rs = [rs]
        spec_roles.update(str(r) for r in rs if r)

        for tool in producer_tools:
            t = _normalize_tool_name(str(tool))
            if not t:
                continue
            expected[t].add(fam)
            roles[t].update(spec_roles)

    for tool, fams in EXTRA_EXPECTED_BY_TOOL.items():
        expected[tool].update(_canonical_family(f) for f in fams)

    return expected, roles


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: check_validation_family_wiring_gate.py STATE_DIR [LOG_PATH]", file=sys.stderr)
        return 2

    state = Path(argv[1])
    log_path = Path(argv[2]) if len(argv) > 2 else None

    all_outputs = _load_json(state / "all_outputs.json")
    if not isinstance(all_outputs, dict):
        all_outputs = {}

    zero_reasons = _zero_reason_map(state)
    evidence_idx = index_evidencedb_families(state / "evidence_db.json")
    db_by_tool_raw = evidence_idx.get("by_tool", {}) if isinstance(evidence_idx, dict) else {}
    db_by_tool: dict[str, Counter[str]] = {}
    for tool, fams in (db_by_tool_raw or {}).items():
        c = Counter()
        if isinstance(fams, dict):
            for fam, count in fams.items():
                c[_canonical_family(str(fam))] += int(count or 0)
        db_by_tool[_normalize_tool_name(str(tool))] = c

    expected_by_tool, roles_by_tool = _registry_by_tool()

    target_tools = set(expected_by_tool)
    target_tools.update(_normalize_tool_name(t) for t in all_outputs.keys())
    target_tools.update(_normalize_tool_name(t) for t in zero_reasons.keys())
    target_tools.update(db_by_tool.keys())
    target_tools.update(_selected_tools_from_log(log_path))

    rows: list[dict[str, Any]] = []
    failures: list[str] = []
    warnings: list[str] = []

    for tool in sorted(t for t in target_tools if t):
        records = _count_records(all_outputs.get(tool))
        zr = zero_reasons.get(tool) or {}
        status = str(zr.get("status") or ("ok" if records > 0 else "zero_records"))
        expected = set(expected_by_tool.get(tool, set()))
        actual = Counter(db_by_tool.get(tool, Counter()))
        actual_fams = set(actual)
        roles = set(roles_by_tool.get(tool, set()))

        verdict = "PASS_ZERO_OR_NONHIT_NO_VALIDATION_REQUIRED"

        if records > 0 or actual_fams:
            if expected:
                unregistered = sorted(actual_fams - expected)
                registered_actual = actual_fams & expected

                if unregistered:
                    verdict = "FAIL_UNREGISTERED_FACT_FAMILY"
                    failures.append(f"{tool}: unregistered fact families {unregistered}")
                elif actual_fams:
                    # SIFT_VALIDATION_FAMILY_CONTEXT_VERDICT_COMPAT_V1F2
                    if roles and not (roles & STRICT_ROLES):
                        verdict = "PASS_CONTEXT_OR_HEALTH_DB_WIRED"
                    else:
                        verdict = "PASS_VALIDATION_FAMILY_WIRED"
                elif roles & STRICT_ROLES:
                    verdict = "FAIL_MISSING_EVIDENCEDB_FAMILY"
                    failures.append(f"{tool}: produced {records} records but no EvidenceDB family")
                else:
                    verdict = "PASS_CONTEXT_OR_HEALTH_DB_WIRED"

                if not registered_actual and actual_fams and roles & STRICT_ROLES:
                    # If a strict producer only emitted unrelated context families, flag it.
                    unrelated = sorted(actual_fams)
                    verdict = "FAIL_MISSING_EXPECTED_EVIDENCEDB_FAMILY"
                    failures.append(
                        f"{tool}: produced DB families {unrelated} but none of expected {sorted(expected)}"
                    )
            else:
                if actual_fams:
                    verdict = "PASS_DB_FAMILY_PRESENT_NO_REGISTERED_TARGET"
                else:
                    verdict = "PASS_ZERO_OR_NONHIT_NO_VALIDATION_REQUIRED"

        rows.append({
            "tool": tool,
            "records": records,
            "status": status,
            "expected": sorted(expected),
            "actual": dict(sorted(actual.items())),
            "roles": sorted(roles),
            "verdict": verdict,
        })

    print("# Validation Family Wiring Gate V3")
    print()
    print(f"- state: `{state}`")
    print(f"- target_tools: `{len(rows)}`")
    print(f"- failures: `{len(failures)}`")
    print(f"- warnings: `{len(warnings)}`")
    print()
    print("| Tool | Records | Status | Expected families | EvidenceDB families | Roles | Verdict |")
    print("|---|---:|---|---|---|---|---|")

    for row in rows:
        expected_s = ", ".join(row["expected"]) if row["expected"] else "-"
        actual_s = ", ".join(f"{k}:{v}" for k, v in row["actual"].items()) if row["actual"] else "-"
        roles_s = ", ".join(row["roles"]) if row["roles"] else "-"
        print(
            f"| `{row['tool']}` | {row['records']} | `{row['status']}` | "
            f"{expected_s} | {actual_s} | {roles_s} | **{row['verdict']}** |"
        )

    if warnings:
        print()
        print("## Warnings")
        for w in warnings:
            print(f"- WARN: {w}")

    if failures:
        print()
        print("## Failures")
        for f in failures:
            print(f"- FAIL: {f}")

    if failures:
        print()
        print("VALIDATION_FAMILY_WIRING_GATE=FAIL")
        return 1

    print()
    print("VALIDATION_FAMILY_WIRING_GATE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
