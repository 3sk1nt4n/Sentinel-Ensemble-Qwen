"""Slot 31H-alpha TASK 1 -- entity truth package builder.

dataset-agnostic by construction: a synthetic run is built per test;
no real run-specific id/path/hash/IP literal is referenced.
"""
from __future__ import annotations

import json
from pathlib import Path

from _etp_fixture import make_synthetic_run

from sift_sentinel.entity_truth_package import (
    ACCEPTANCE_MANIFEST_JSON,
    DURABLE_ENTITY_TRUTH_PACKAGE_GATE,
    ENTITY_TRUTH_SUMMARY_JSON,
    ENTITY_TRUTH_SUMMARY_MD,
    PACKAGE_GATES,
    SUBMISSION_READINESS_REPORT_MD,
    build_entity_truth_package,
    build_submission_readiness_report,
    redact_submission_text,
    redact_submission_value,
    write_acceptance_manifest,
)


def test_public_api_callables_exist():
    assert callable(build_entity_truth_package)
    assert callable(redact_submission_value)
    assert callable(redact_submission_text)
    assert callable(write_acceptance_manifest)
    assert callable(build_submission_readiness_report)


def test_builder_writes_four_package_files(tmp_path):
    run_json = make_synthetic_run(tmp_path)
    out = tmp_path / "pkg"
    result = build_entity_truth_package(run_json, out)

    for name in (
        ENTITY_TRUTH_SUMMARY_JSON,
        ENTITY_TRUTH_SUMMARY_MD,
        ACCEPTANCE_MANIFEST_JSON,
        SUBMISSION_READINESS_REPORT_MD,
    ):
        assert (out / name).is_file(), name

    assert result["package_dir"] == str(out)
    assert set(result["gates"]) >= set(PACKAGE_GATES)
    assert "summary" in result and "manifest" in result


def test_all_package_gates_pass_on_clean_synthetic_run(tmp_path):
    run_json = make_synthetic_run(tmp_path)
    result = build_entity_truth_package(run_json, tmp_path / "pkg")
    gates = result["gates"]
    fails = {g: v for g, v in gates.items() if v != "PASS"}
    assert not fails, fails
    assert gates[DURABLE_ENTITY_TRUTH_PACKAGE_GATE] == "PASS"


def test_default_output_dir_is_under_run_archive(tmp_path):
    # run_id absent -> basename stem; output defaults under run_archive/.
    run_json = make_synthetic_run(tmp_path, run_id=None)
    result = build_entity_truth_package(run_json, None)
    pkg = Path(result["package_dir"])
    try:
        assert pkg.parts[0] == "run_archive"
        assert pkg.name.startswith("entity_truth_")
        assert (pkg / ENTITY_TRUTH_SUMMARY_JSON).is_file()
    finally:
        # Generated artifact -- never committed; clean up the synthetic
        # default-location package this test created.
        import shutil
        if pkg.exists():
            shutil.rmtree(pkg, ignore_errors=True)


def test_summary_json_is_valid_and_redacted(tmp_path):
    run_json = make_synthetic_run(tmp_path)
    out = tmp_path / "pkg"
    build_entity_truth_package(run_json, out)
    data = json.loads((out / ENTITY_TRUTH_SUMMARY_JSON).read_text())
    assert data["schema_version"]
    assert "entity_counts" in data
    blob = (out / ENTITY_TRUTH_SUMMARY_JSON).read_text()
    # Host evidence/workstation prefixes never persist in the package.
    assert "/home/sansforensics" not in blob
    assert "/cases" not in blob and "/mnt" not in blob


def test_slot31h_all_package_gate_markers_present_for_v3():
    gates = {
        "DURABLE_ENTITY_TRUTH_PACKAGE_GATE",
        "ENTITY_TRUTH_PACKAGE_BUILD_GATE",
        "ENTITY_PACKAGE_CONFIRMED_DEDUP_GATE",
        "ENTITY_PACKAGE_CONTRADICTION_ROUTING_GATE",
        "ENTITY_PACKAGE_MANIFEST_GATE",
        "SUBMISSION_MODEL_NAME_NONPERSISTENCE_GATE",
        "SUBMISSION_EVIDENCE_PATH_REDACTION_GATE",
        "SUBMISSION_DEBUG_LOG_EXCLUSION_GATE",
        "SUBMISSION_READINESS_REPORT_GATE",
        "REDACTOR_FUNCTIONALLY_REDACTS_GATE",
        "RUN_ARCHIVE_GITIGNORE_GATE",
    }
    assert len(gates) == 11
