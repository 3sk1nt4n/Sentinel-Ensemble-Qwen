"""Deterministic findings for process ancestry violations.

Dataset-agnostic policy:
- Uses OS process-parent invariants already computed by
  validation.ancestry.check_ancestry().
- Emits validator-backed findings only from observed parent-child relationships.
- No hidden reference markers, no dataset-specific literals, no IOCs, no promotion from LLM text.
- Pure helpers: no I/O, no saved state.
"""

from __future__ import annotations

import re
from typing import Any, Iterable


_SCHEMA_VERSION = "ancestry_violation_findings_v1"
_SEMANTIC_SIGNAL = "process_ancestry_violation"


def _as_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _finding_id(finding: dict[str, Any] | None) -> str:
    if not isinstance(finding, dict):
        return ""
    return str(
        finding.get("finding_id")
        or finding.get("id")
        or finding.get("fid")
        or ""
    ).strip()


def _next_finding_id(existing_findings: Iterable[dict[str, Any]] | None) -> str:
    max_n = 0
    width = 3
    for finding in existing_findings or []:
        fid = _finding_id(finding)
        m = re.fullmatch(r"F(\d+)", fid)
        if not m:
            continue
        digits = m.group(1)
        width = max(width, len(digits))
        max_n = max(max_n, int(digits))
    return "F%0*d" % (width, max_n + 1)


def _bump_finding_id(fid: str) -> str:
    m = re.fullmatch(r"F(\d+)", str(fid or ""))
    if not m:
        return "F001"
    digits = m.group(1)
    return "F%0*d" % (len(digits), int(digits) + 1)


def _edge_from_violation(violation: dict[str, Any] | None) -> tuple[int, int] | None:
    if not isinstance(violation, dict):
        return None
    child_pid = _as_int(violation.get("pid"))
    parent_pid = _as_int(violation.get("parent_pid"))
    if child_pid is None or parent_pid is None:
        return None
    return parent_pid, child_pid


def _existing_child_process_edges(findings: Iterable[dict[str, Any]] | None) -> set[tuple[int, int]]:
    edges: set[tuple[int, int]] = set()
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        for claim in finding.get("claims") or []:
            if not isinstance(claim, dict):
                continue
            if str(claim.get("type") or "").lower() != "child_process":
                continue
            parent_pid = _as_int(claim.get("parent_pid"))
            child_pid = _as_int(claim.get("child_pid"))
            if parent_pid is not None and child_pid is not None:
                edges.add((parent_pid, child_pid))
    return edges


def _clean_expected(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(x).strip() for x in value if str(x).strip()]
    s = str(value).strip()
    return [s] if s else []


def build_ancestry_violation_findings(
    ancestry_violations: Iterable[dict[str, Any]] | None,
    existing_findings: Iterable[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Build deterministic validator-backed findings from ancestry violations.

    Returns only new findings. If an existing finding already contains the exact
    child_process edge, no duplicate is emitted.
    """
    existing = list(existing_findings or [])
    existing_edges = _existing_child_process_edges(existing)
    used_edges = set(existing_edges)
    out: list[dict[str, Any]] = []
    next_id = _next_finding_id(existing)

    sortable: list[tuple[int, int, dict[str, Any]]] = []
    for violation in ancestry_violations or []:
        edge = _edge_from_violation(violation)
        if edge is None:
            continue
        sortable.append((edge[1], edge[0], dict(violation)))

    for _child_pid_sort, _parent_pid_sort, violation in sorted(sortable):
        edge = _edge_from_violation(violation)
        if edge is None or edge in used_edges:
            continue

        parent_pid, child_pid = edge
        child_process = str(violation.get("process") or "unknown_process").strip()
        parent_process = str(violation.get("actual_parent") or "unknown_parent").strip()
        expected = _clean_expected(violation.get("expected_parents"))

        expected_text = ", ".join(expected) if expected else "known expected parent"
        title = (
            "Unexpected process ancestry: %s parented by %s"
            % (child_process, parent_process)
        )
        description = (
            "%s (PID %d) is parented by %s (PID %d), but the canonical "
            "OS parent invariant expects %s. The relationship itself is "
            "validator-backed by the process tree; the suspiciousness comes "
            "from the invariant violation, not from an LLM assertion."
            % (child_process, child_pid, parent_process, parent_pid, expected_text)
        )

        finding = {
            "finding_id": next_id,
            "id": next_id,
            "title": title,
            "description": description,
            "severity": "HIGH",
            "confidence": "HIGH",
            "confidence_level": "HIGH",
            "source_tools": ["vol_pstree"],
            "tool_call_ids": ["vol_pstree"],
            "deterministic_finding": True,
            "deterministic_kind": "process_ancestry_violation",
            "schema_version": _SCHEMA_VERSION,
            "child_pid": child_pid,
            "parent_pid": parent_pid,
            "child_process": child_process,
            "parent_process": parent_process,
            "expected_parent_processes": expected,
            "actual_parent_process": parent_process,
            "malicious_semantic_signals": [_SEMANTIC_SIGNAL],
            "malicious_semantic_provenance": {
                _SEMANTIC_SIGNAL: {
                    "source": "check_ancestry",
                    "source_tool": "vol_pstree",
                    "child_pid": child_pid,
                    "parent_pid": parent_pid,
                    "child_process": child_process,
                    "parent_process": parent_process,
                    "expected_parent_processes": expected,
                }
            },
            "claims": [
                {
                    "type": "child_process",
                    "parent_pid": parent_pid,
                    "child_pid": child_pid,
                },
                {
                    "type": "pid",
                    "pid": child_pid,
                    "process": child_process,
                },
                {
                    "type": "pid",
                    "pid": parent_pid,
                    "process": parent_process,
                },
            ],
        }
        out.append(finding)
        used_edges.add(edge)
        next_id = _bump_finding_id(next_id)

    return out


def audit_ancestry_violation_coverage(
    ancestry_violations: Iterable[dict[str, Any]] | None,
    findings: Iterable[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Check that every detected ancestry edge is covered by a child_process claim."""
    expected_edges = {
        edge for edge in (_edge_from_violation(v) for v in ancestry_violations or [])
        if edge is not None
    }
    covered_edges = _existing_child_process_edges(findings)
    missing_edges = sorted(expected_edges - covered_edges)
    return {
        "schema_version": _SCHEMA_VERSION,
        "gate": "PASS" if not missing_edges else "FAIL",
        "violation_count": len(expected_edges),
        "covered_count": len(expected_edges) - len(missing_edges),
        "missing_count": len(missing_edges),
        "missing_edges": [
            {"parent_pid": parent_pid, "child_pid": child_pid}
            for parent_pid, child_pid in missing_edges
        ],
    }


__all__ = [
    "build_ancestry_violation_findings",
    "audit_ancestry_violation_coverage",
]
