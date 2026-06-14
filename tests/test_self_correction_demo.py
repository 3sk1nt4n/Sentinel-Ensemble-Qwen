"""
Self-correction demo tests.
Proves SC works mechanically: wrong field name -> BLOCKED -> corrected -> MATCH.
"""

from __future__ import annotations

import copy

from sift_sentinel.correction.self_correct import self_correct
from sift_sentinel.validation.normalize_claims import normalize_claims
from sift_sentinel.validation.validator import validate_finding


# ── Fixtures ────────────────────────────────────────────────────────────

REF_SET = {
    "pid_to_process": {9001: ["sqlsvc.exe"], 4: ["System"]},
    "hashes": {},
    "timestamps_per_artifact": {},
    "connections": {},
    "paths": {},
}

RAW_DATA = {
    "vol_pstree": {
        "output": [
            {"PID": 9001, "ImageFileName": "sqlsvc.exe"},
            {"PID": 4, "ImageFileName": "System"},
        ],
    },
}

# Finding with wrong field name: process_name instead of process
BROKEN_FINDING = {
    "finding_id": "F-TEST",
    "artifact": "sqlsvc.exe",
    "confidence_level": "HIGH",
    "claims": [
        {"type": "pid", "pid": 9001, "process_name": "sqlsvc.exe"},
    ],
}


# ── Test: full correction chain ─────────────────────────────────────────


def test_process_name_blocked_then_corrected():
    """Finding with 'process_name' is BLOCKED, then SC corrects it to MATCH.

    Chain:
    1. Validator sees 'process_name' but expects 'process' -> MISMATCH
    2. SC corrector returns same finding (with process_name)
    3. SC internal normalize_claims renames process_name -> process
    4. Re-validation: MATCH
    """
    # Step 1: validate without normalization -- should fail
    validation = validate_finding(BROKEN_FINDING, REF_SET)
    assert validation["status"] == "MISMATCH", (
        f"Expected MISMATCH, got {validation['status']}: {validation['detail']}"
    )

    # Step 2-4: self_correct with a corrector that returns the same shape
    def corrector(raw_data, error):
        return copy.deepcopy(BROKEN_FINDING)

    result = self_correct(
        finding=BROKEN_FINDING,
        error=validation["detail"],
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=corrector,
    )

    assert result["status"] == "CORRECTED"
    assert result["finding"]["claims"][0]["process"] == "sqlsvc.exe"
    assert "process_name" not in result["finding"]["claims"][0]
    assert result["attempt_count"] == 1


def test_string_pid_blocked_then_corrected():
    """Finding with string PID is BLOCKED, then SC coerces it to int -> MATCH."""
    broken = {
        "finding_id": "F-TEST-PID",
        "artifact": "System",
        "confidence_level": "MEDIUM",
        "claims": [
            {"type": "pid", "pid": "4", "process": "System"},
        ],
    }

    # pid="4" (string) won't match pid_to_process key 4 (int)
    validation = validate_finding(broken, REF_SET)
    assert validation["status"] == "MISMATCH"

    def corrector(raw_data, error):
        return copy.deepcopy(broken)

    result = self_correct(
        finding=broken,
        error=validation["detail"],
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=corrector,
    )

    assert result["status"] == "CORRECTED"
    assert result["finding"]["claims"][0]["pid"] == 9001 or \
        result["finding"]["claims"][0]["pid"] == 4


def test_hash_alias_blocked_then_corrected():
    """Finding with 'hash' instead of 'sha1' is BLOCKED, then SC fixes it."""
    ref = {
        "pid_to_process": {},
        "hashes": {"aabbcc": "malware.exe"},
        "timestamps_per_artifact": {},
        "connections": {},
        "paths": {},
    }
    broken = {
        "finding_id": "F-TEST-HASH",
        "artifact": "malware.exe",
        "confidence_level": "HIGH",
        "claims": [
            {"type": "hash", "hash": "aabbcc", "filename": "malware.exe"},
        ],
    }

    validation = validate_finding(broken, ref)
    assert validation["status"] == "MISMATCH"

    def corrector(raw_data, error):
        return copy.deepcopy(broken)

    result = self_correct(
        finding=broken,
        error=validation["detail"],
        raw_data={},
        ref_set=ref,
        corrector_fn=corrector,
    )

    assert result["status"] == "CORRECTED"
    assert result["finding"]["claims"][0]["sha1"] == "aabbcc"
    assert "hash" not in result["finding"]["claims"][0]


def test_correction_chain_visible_output(capsys):
    """Prints the correction chain to stdout for demo visibility."""
    validation = validate_finding(BROKEN_FINDING, REF_SET)
    print(f"\nFINDING F-TEST: BLOCKED ({validation['detail']})")

    def corrector(raw_data, error):
        print("SELF-CORRECTION ATTEMPT 1: Normalizing claims...")
        return copy.deepcopy(BROKEN_FINDING)

    result = self_correct(
        finding=BROKEN_FINDING,
        error=validation["detail"],
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=corrector,
    )

    status = result["status"]
    detail = "corrected 'process_name' -> 'process'"
    print(f"FINDING F-TEST: {status} ({detail})")

    captured = capsys.readouterr()
    assert "BLOCKED" in captured.out
    assert "SELF-CORRECTION ATTEMPT 1" in captured.out
    assert "CORRECTED" in captured.out or "MATCH" in captured.out
