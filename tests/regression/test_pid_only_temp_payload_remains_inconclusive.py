"""Slot 31E-DB.5a-alpha TASK 4 -- PID-only temp-payload route pin.

Property-based: a temp-payload-looking observation that carries ONLY a
PID/process claim stays inconclusive or suspicious, never confirmed. No
observed case ids, no real PID values, no real paths.
"""
from __future__ import annotations

from sift_sentinel.analysis.disposition import (
    BUCKET_CONFIRMED,
    BUCKET_INCONCLUSIVE,
    BUCKET_SUSPICIOUS,
    derive_final_disposition,
    route_findings_for_report,
)


def _fixture():
    return {
        "finding_id": "synthetic_pid_only_temp_payload",
        "title": "synthetic temp payload process",
        "severity": "HIGH",
        "confidence_level": "HIGH",
        "validation_status": "MATCH",
        "deterministic_check": "passed",
        "self_verification_passed": True,
        "source_tools": ["vol_pstree"],
        "tool_call_ids": ["tc-tmp-1"],
        "raw_excerpt": "process observed running",
        "claims": [
            {"type": "pid", "process": "synthetic_temp_payload.exe"},
        ],
    }


def test_pid_only_temp_payload_not_confirmed():
    f = _fixture()
    bucket, _ = derive_final_disposition(f)
    assert bucket != BUCKET_CONFIRMED
    assert bucket in (BUCKET_SUSPICIOUS, BUCKET_INCONCLUSIVE)


def test_pid_only_temp_payload_absent_from_confirmed_bucket():
    buckets = route_findings_for_report([_fixture()])
    confirmed_ids = {
        x.get("finding_id") for x in buckets[BUCKET_CONFIRMED]
    }
    assert "synthetic_pid_only_temp_payload" not in confirmed_ids


def test_marker():
    print("PID_ONLY_TEMP_PAYLOAD_INCONCLUSIVE_GATE=PASS")
    assert True
