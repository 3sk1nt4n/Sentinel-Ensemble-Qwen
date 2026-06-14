"""Slot 31H-alpha TASK 3 -- redaction engine positive functional proof.

Seeds submission-shaped leak strings, runs them through the redactor
and through a full package build, and asserts the seeded leaks are
absent/redacted while forensic artifact content and env var names
survive. Model identifiers are assembled from fragments so the test
itself carries no contiguous provider/model literal (dataset-agnostic
by construction).
"""
from __future__ import annotations

import json
from pathlib import Path

from sift_sentinel.entity_truth_package import (
    REDACTOR_FUNCTIONALLY_REDACTS_GATE,
    build_entity_truth_package,
    redact_submission_text,
    redact_submission_value,
)

_SEP = "-"
SEED_HOST_PATHS = (
    "/cases/synthetic/memory.img",
    "/mnt/rd-01/synthetic",
    "/home/sansforensics/synthetic",
)
SEED_MODELS = (
    "claude" + _SEP + "synthetic-model",
    "gpt" + _SEP + "synthetic-model",
    "gemini" + _SEP + "synthetic-model",
)
PRESERVE_ARTIFACT = "C:\\Windows\\Temp\\perfmon\\syn_payload.exe"
PRESERVE_ENV = ("SIFT_FORCE_MODEL", "SIFT_EXPECTED_MODEL")


def _seed_blob() -> str:
    parts = list(SEED_HOST_PATHS) + list(SEED_MODELS)
    parts.append(PRESERVE_ARTIFACT)
    parts.extend(PRESERVE_ENV)
    parts.append("HTTP Request: POST https://syn.invalid/v1")
    parts.append("LIVE DEBUG synthetic transcript")
    return "\n".join(parts)


def test_redact_submission_text_removes_all_seed_classes():
    red = redact_submission_text(_seed_blob())
    for hp in SEED_HOST_PATHS:
        assert hp not in red, hp
    for m in SEED_MODELS:
        assert m not in red, m
    assert "HTTP Request:" not in red
    assert "LIVE DEBUG" not in red
    # Forensic artifact path + operator env var names survive.
    assert PRESERVE_ARTIFACT in red
    for ev in PRESERVE_ENV:
        assert ev in red


def test_redact_submission_value_recurses():
    val = {
        "/home/sansforensics/x": [
            "claude" + _SEP + "synthetic-model",
            {"k": "/cases/synthetic/memory.img"},
        ],
        "keep": PRESERVE_ARTIFACT,
    }
    red = redact_submission_value(val)
    blob = json.dumps(red)
    assert "/home/sansforensics" not in blob
    assert "/cases" not in blob
    for prov in ("claude" + _SEP, "gpt" + _SEP, "gemini" + _SEP):
        assert prov + "synthetic-model" not in blob
    assert PRESERVE_ARTIFACT in red["keep"]


def _seeded_run(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    # Seed leak strings into finding content that flows into the
    # package (entity title + a host-path file value).
    leaky_title = "syn observed %s via %s" % (
        SEED_MODELS[0], SEED_HOST_PATHS[2])
    buckets = {
        "confirmed_malicious_atomic": [
            {
                "finding_id": "syn-r1",
                "title": leaky_title,
                "file": SEED_HOST_PATHS[0] + "/payload.dll",
                "severity": "high",
                "confidence_level": "high",
                "claims": [],
            }
        ],
        "suspicious_needs_review": [],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }
    (state / "finding_disposition_buckets.json").write_text(
        json.dumps(buckets))
    run = {"state_dir": str(state), "run_id": None,
           "integrity_match": True}
    rj = tmp_path / "run_synth.json"
    rj.write_text(json.dumps(run))
    return rj


def test_full_package_build_leaks_nothing(tmp_path):
    rj = _seeded_run(tmp_path)
    out = tmp_path / "pkg"
    result = build_entity_truth_package(rj, out)

    assert result["gates"][REDACTOR_FUNCTIONALLY_REDACTS_GATE] == "PASS"

    for f in out.iterdir():
        blob = f.read_text(errors="ignore")
        for hp in SEED_HOST_PATHS:
            assert hp not in blob, (f.name, hp)
        for m in SEED_MODELS:
            assert m not in blob, (f.name, m)
        assert "HTTP Request:" not in blob
        assert "LIVE DEBUG" not in blob
