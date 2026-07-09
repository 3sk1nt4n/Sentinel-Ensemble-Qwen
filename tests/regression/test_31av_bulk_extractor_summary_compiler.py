"""slot31AV regression: bulk_extractor is registered as a summary-only
typed-fact compiler so the EvidenceDB coverage gate stops flagging it
as a silent-drop tool.

Honest record_count was a prerequisite (run_bulk_extractor envelope
now returns record_count=1 with one summary record). This regression
locks in the second half of that fix:

  * _TOOL_COMPILERS has a ``run_bulk_extractor`` entry,
  * the compiler emits exactly ONE ``ioc_carve_summary_fact`` per
    summary record carrying the carved feature counts,
  * coverage reconciles (record_count == compiled + dropped),
  * the gate snapshot no longer lists run_bulk_extractor under
    silent_dropped or zero_typed_fact_families,
  * the summary fact has NO entity / PID / IP / path / URL / hash
    fields, so it produces ZERO candidate observations and cannot
    inflate validation-ready or candidate totals.

Dataset-agnostic: fabricated counts only, no real evidence paths.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sift_sentinel.analysis.candidate_observations import (  # noqa: E402
    build_candidate_observations,
)
from sift_sentinel.analysis.drift_gate import (  # noqa: E402
    build_evidencedb_coverage_snapshot,
    validate_evidencedb_coverage_snapshot,
)
from sift_sentinel.analysis.evidence_db import (  # noqa: E402
    FACT_TYPES,
    _TOOL_COMPILERS,
    build_typed_evidence_db,
)


def _summary_envelope(*, emails=100, urls=200, domains=300, total=None):
    if total is None:
        total = emails + urls + domains
    return {
        "tool_name": "run_bulk_extractor",
        "evidence_path": "/fixture/synthetic.img",
        "execution_time_ms": 1234,
        "record_count": 1,
        "output": [{
            "emails": emails,
            "urls": urls,
            "domains": domains,
            "carved_feature_total": total,
        }],
    }


# ── registration ───────────────────────────────────────────────────


def test_run_bulk_extractor_is_registered_in_tool_compilers():
    assert "run_bulk_extractor" in _TOOL_COMPILERS, (
        "run_bulk_extractor must be a registered compiler so the "
        "EvidenceDB coverage gate does not flag it as a silent drop."
    )


def test_ioc_carve_summary_fact_is_in_FACT_TYPES():
    assert "ioc_carve_summary_fact" in FACT_TYPES


# ── compiler shape ─────────────────────────────────────────────────


def test_compiler_emits_exactly_one_fact_per_summary_record():
    env = _summary_envelope(emails=10, urls=20, domains=30)
    db = build_typed_evidence_db({"run_bulk_extractor": env})
    facts = db["typed_facts"]["ioc_carve_summary_fact"]
    assert len(facts) == 1, facts
    f = facts[0]
    assert f["fact_type"] == "ioc_carve_summary_fact"
    assert f["emails"] == 10
    assert f["urls"] == 20
    assert f["domains"] == 30
    assert f["carved_feature_total"] == 60


def test_compiler_defaults_carved_feature_total_when_missing():
    env = _summary_envelope(emails=1, urls=2, domains=3, total=None)
    env["output"][0].pop("carved_feature_total")
    db = build_typed_evidence_db({"run_bulk_extractor": env})
    f = db["typed_facts"]["ioc_carve_summary_fact"][0]
    assert f["carved_feature_total"] == 6


def test_fact_carries_no_entity_or_observable_artifact_fields():
    """The summary fact must be unenrichable: no entity_id, no PID,
    no IP, no path, no URL, no hash, no registry - so it cannot
    surface as a candidate observation. raw_excerpt holds the count
    counts only (NOT the carved text), so _entity_keys URL/IP regex
    finds nothing.
    """
    env = _summary_envelope()
    db = build_typed_evidence_db({"run_bulk_extractor": env})
    f = db["typed_facts"]["ioc_carve_summary_fact"][0]
    forbidden_keys = {
        "pid", "PID", "process_name", "image_name",
        "path", "normalized_path", "file_path", "Path",
        "src_ip", "dst_ip", "LocalAddr", "ForeignAddr",
        "service_name", "task_name", "registry_path",
        "hash", "sha256", "md5",
    }
    assert forbidden_keys.isdisjoint(f.keys()), (
        f"summary fact must not carry observable-entity fields: "
        f"{sorted(forbidden_keys & f.keys())}"
    )
    assert f["entity_id"] == ""
    raw = json.loads(f["raw_excerpt"])
    assert set(raw.keys()) == {
        "emails", "urls", "domains", "carved_feature_total"
    }


# ── coverage reconciliation ────────────────────────────────────────


def test_coverage_reconciles_one_to_one():
    env = _summary_envelope()
    db = build_typed_evidence_db({"run_bulk_extractor": env})
    cov = db["coverage"]["per_tool"]["run_bulk_extractor"]
    assert cov["record_count"] == 1
    assert cov["compiled_record_count"] == 1
    assert cov["dropped_record_count"] == 0
    assert cov["reconciliation_ok"] is True
    assert cov["fact_types"] == ["ioc_carve_summary_fact"]


def test_coverage_snapshot_not_blocked_by_silent_drop_or_zero_family():
    env = _summary_envelope()
    db = build_typed_evidence_db({"run_bulk_extractor": env})
    snap = build_evidencedb_coverage_snapshot(
        db, {"run_bulk_extractor": env},
    )
    assert "run_bulk_extractor" in snap["per_tool"]
    assert "run_bulk_extractor" not in (
        snap.get("silent_dropped_tools_without_compiler") or []
    )
    families = snap.get(
        "zero_typed_fact_families_for_nonempty_source_tools") or []
    flat_sources = {
        s for entry in families for s in entry.get(
            "nonempty_raw_sources") or []
    }
    assert "run_bulk_extractor" not in flat_sources
    assert snap["all_reconciled"] is True
    errors = [v for v in validate_evidencedb_coverage_snapshot(snap)
              if v.get("severity") == "error"]
    bulk_errors = [e for e in errors
                   if "bulk_extractor" in e.get("message", "")
                   or "bulk_extractor" in str(e.get("details", {}))]
    assert not bulk_errors, bulk_errors


# ── candidate isolation ────────────────────────────────────────────


def test_summary_fact_produces_no_candidate_observation():
    """The summary fact must never enter candidate generation.
    Running the candidate builder with ONLY the summary fact present
    must yield zero candidates and zero validation-ready candidates.
    """
    env = _summary_envelope()
    db = build_typed_evidence_db({"run_bulk_extractor": env})
    co = build_candidate_observations(db)
    assert co["total_facts"] == 1
    assert co["candidate_count"] == 0
    assert co["validation_ready_count"] == 0
    assert co["candidates"] == []


def test_other_tools_still_protected_by_silent_drop_gate():
    """Sanity guard: registering bulk_extractor must NOT weaken the
    gate. A truly unknown tool with records must still be flagged.
    """
    fake_env = {
        "tool_name": "synthetic_unknown_tool",
        "record_count": 5,
        "output": [{"foo": i} for i in range(5)],
    }
    snap = build_evidencedb_coverage_snapshot(
        build_typed_evidence_db({"synthetic_unknown_tool": fake_env}),
        {"synthetic_unknown_tool": fake_env},
    )
    assert "synthetic_unknown_tool" in (
        snap.get("silent_dropped_tools_without_compiler") or []
    )
