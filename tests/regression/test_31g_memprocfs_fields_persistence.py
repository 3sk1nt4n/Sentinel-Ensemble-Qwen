"""31G-MEMPROCFS-FIELDS-PERSISTENCE.

MemProcFS / FindEvil records are valuable only if normalized fields
survive into typed EvidenceDB facts. This test catches the previous
failure mode where pid/process/indicator/priority/path existed only
inside raw_excerpt and disappeared from the materialized fact.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from sift_sentinel.analysis import evidence_db as edb
from sift_sentinel.analysis.phase1_extractors import _c_memprocfs


def _sample_memprocfs_record() -> dict[str, Any]:
    return {
        "source_tool": "run_memprocfs",
        "source_csv": "findevil.csv",
        "memprocfs_subsystem": "forensic_csv",
        "semantic_family": "findevil_indicators",
        "semantic_role": "anomaly_indicator",
        "families": ["memory", "findevil_indicators"],
        "priority_tier": "CRITICAL",
        "evidence_id": "memprocfs:findevil:synthetic",
        "pid": "8128",
        "process": "OUTLOOK.EXE",
        "anchors": {
            "pid": "8128",
            "process_name": "OUTLOOK.EXE",
            "process_path": r"\Device\HarddiskVolume2\Program Files\Microsoft Office\OUTLOOK.EXE",
        },
        "indicator_type": "HIGH_ENTROPY",
        "description": "Entropy:[7.65] p-rw--",
        "fields": {"Address": "0x23d10000"},
        "path": r"\Device\HarddiskVolume2\Program Files\Microsoft Office\OUTLOOK.EXE",
    }


def _walk_dicts(obj: Any):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk_dicts(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_dicts(v)


def _try_build_evidence_db(tool_outputs: dict[str, Any]) -> Any:
    """Call the repository's current EvidenceDB builder without assuming
    a single historical function name.
    """
    candidate_names = [
        "build_evidence_db",
        "build_typed_evidence_db",
        "build_paired_reference_set",
        "compile_evidence_db",
        "compile_tool_outputs",
        "build_from_tool_outputs",
    ]

    errors: list[str] = []
    for name in candidate_names:
        fn = getattr(edb, name, None)
        if not callable(fn):
            continue

        attempts = [
            ((tool_outputs,), {}),
            ((tool_outputs,), {"evidence_hashes": {}}),
            ((), {"tool_outputs": tool_outputs}),
            ((), {"tool_outputs": tool_outputs, "evidence_hashes": {}}),
        ]
        for args, kwargs in attempts:
            try:
                sig = inspect.signature(fn)
                sig.bind_partial(*args, **kwargs)
            except Exception:
                pass

            try:
                return fn(*args, **kwargs)
            except TypeError as exc:
                errors.append(f"{name}{args}{kwargs}: {exc}")
            except Exception as exc:
                errors.append(f"{name}{args}{kwargs}: {type(exc).__name__}: {exc}")

    raise AssertionError(
        "Could not invoke any EvidenceDB builder; tried "
        + ", ".join(candidate_names)
        + " errors="
        + " | ".join(errors[:8])
    )


def _find_memprocfs_facts(obj: Any) -> list[dict[str, Any]]:
    return [
        d for d in _walk_dicts(obj)
        if isinstance(d, dict) and d.get("fact_type") == "memprocfs_indicator_fact"
    ]


def test_memprocfs_compiler_emits_fields_and_index_payload() -> None:
    emitted = list(_c_memprocfs([_sample_memprocfs_record()]))
    assert len(emitted) == 1

    _idx, fact, reason = emitted[0]
    assert reason is None
    assert fact is not None

    fields = fact.get("fields") or {}
    assert fields["pid"] == 8128
    assert fields["process_name"] == "outlook.exe"
    assert fields["indicator_type"] == "high_entropy"
    assert fields["priority_tier"] == "critical"
    assert fields["semantic_family"] == "findevil_indicators"
    assert fields["semantic_role"] == "anomaly_indicator"
    assert fields["source_csv"] == "findevil.csv"
    assert fields["source_file"] == "findevil.csv"
    assert "outlook.exe" in fields["path"]

    index = fact.get("index") or {}
    assert index["by_pid"] == ["8128"]
    assert index["by_path"]


def test_memprocfs_fields_survive_typed_evidencedb_materialization() -> None:
    tool_outputs = {
        "run_memprocfs": {
            "tool_name": "run_memprocfs",
            "output": [_sample_memprocfs_record()],
            "records": [_sample_memprocfs_record()],
            "record_count": 1,
        }
    }

    db = _try_build_evidence_db(tool_outputs)
    facts = _find_memprocfs_facts(db)
    assert facts, "EvidenceDB builder emitted no memprocfs_indicator_fact"

    fact = facts[0]

    # The exact materializer may flatten fields into top-level keys or retain
    # a nested fields object. Accept either, but raw_excerpt-only is not enough.
    nested = fact.get("fields") if isinstance(fact.get("fields"), dict) else {}

    def val(key: str):
        return fact.get(key, nested.get(key))

    assert val("pid") == 8128
    assert str(val("process_name")).lower() == "outlook.exe"
    assert val("indicator_type") == "high_entropy"
    assert val("priority_tier") == "critical"
    assert val("semantic_family") == "findevil_indicators"
    assert val("semantic_role") == "anomaly_indicator"
    assert val("source_csv") == "findevil.csv"
    assert val("source_file") == "findevil.csv"
    assert "outlook.exe" in str(val("path")).lower()
