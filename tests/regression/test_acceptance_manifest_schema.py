"""Slot 31H-alpha TASK 2 -- acceptance_manifest.json locked schema.

dataset-agnostic by construction.
"""
from __future__ import annotations

import hashlib
import json

from _etp_fixture import make_synthetic_run

from sift_sentinel.entity_truth_package import (
    ACCEPTANCE_MANIFEST_JSON,
    PACKAGE_GATES,
    build_entity_truth_package,
)

_EXPECTED_TOP_KEYS = {
    "schema_version",
    "package_built_at_epoch",
    "source_run_id",
    "source_head",
    "source_run_json_basename",
    "redaction_applied",
    "model_names_redacted",
    "debug_logs_excluded",
    "package_files",
    "package_file_sha256",
    "gates_at_build_time",
}

_EXPECTED_PACKAGE_FILES = [
    "entity_truth_summary.json",
    "entity_truth_summary.md",
    "submission_readiness_report.md",
]


def _manifest(tmp_path):
    run_json = make_synthetic_run(tmp_path)
    out = tmp_path / "pkg"
    build_entity_truth_package(run_json, out)
    return json.loads((out / ACCEPTANCE_MANIFEST_JSON).read_text()), out


def test_manifest_exact_top_level_keys(tmp_path):
    m, _ = _manifest(tmp_path)
    assert set(m) == _EXPECTED_TOP_KEYS


def test_manifest_static_flags_and_types(tmp_path):
    m, _ = _manifest(tmp_path)
    assert m["schema_version"] == "1.0"
    assert isinstance(m["package_built_at_epoch"], int)
    assert m["redaction_applied"] is True
    assert m["model_names_redacted"] is True
    assert m["debug_logs_excluded"] is True
    assert m["package_files"] == _EXPECTED_PACKAGE_FILES


def test_source_run_json_basename_is_basename_only(tmp_path):
    m, _ = _manifest(tmp_path)
    b = m["source_run_json_basename"]
    assert "/" not in b and "\\" not in b
    assert b == "run_synth.json"
    # run_id absent -> stem used.
    assert m["source_run_id"] == "run_synth"


def test_package_file_sha256_hashes_generated_files(tmp_path):
    m, out = _manifest(tmp_path)
    sha = m["package_file_sha256"]
    assert set(sha) == set(_EXPECTED_PACKAGE_FILES)
    for name, digest in sha.items():
        actual = hashlib.sha256((out / name).read_bytes()).hexdigest()
        assert actual == digest, name


def test_gates_at_build_time_covers_all_package_gates(tmp_path):
    m, _ = _manifest(tmp_path)
    g = m["gates_at_build_time"]
    assert set(g) == set(PACKAGE_GATES)
    assert all(v == "PASS" for v in g.values()), g


def test_manifest_carries_no_model_name_or_host_path(tmp_path):
    m, _ = _manifest(tmp_path)
    blob = json.dumps(m)
    for prov in ("claude" + "-", "gpt" + "-", "gemini" + "-"):
        assert prov not in blob.lower()
    for host in ("/cases", "/mnt", "/home/sansforensics"):
        assert host not in blob
