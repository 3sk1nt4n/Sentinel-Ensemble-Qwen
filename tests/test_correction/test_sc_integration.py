"""
Sentinel Qwen Ensemble - Self-correction INTEGRATION tests.
Uses REAL validator.py + reference_set.py. Only the corrector is mocked.
Proves the full chain: validate -> self_correct -> re-validate.
"""

from __future__ import annotations

import copy
import json
import os

from sift_sentinel.correction.self_correct import self_correct
from sift_sentinel.validation.reference_set import build_reference_set
from sift_sentinel.validation.validator import validate_finding


# ── Shared tool outputs (fed to build_reference_set) ───────────────────

TOOL_OUTPUTS = {
    "vol_pstree": {
        "output": [
            {"PID": 9001, "ImageFileName": "sample_payload.exe",
             "CreateTime": "2018-04-11T14:22:07Z"},
            {"PID": 4, "ImageFileName": "System"},
            {"PID": 1234, "ImageFileName": "svchost.exe"},
        ],
    },
    "get_amcache": {
        "output": [
            {"sha1": "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30",
             "path": r"C:\Windows\Temp\sample_payload.exe",
             "first_run": "2018-04-11 14:22:07"},
        ],
    },
}

RAW_DATA = TOOL_OUTPUTS

# Build reference set ONCE from real tool outputs
REF_SET = build_reference_set(TOOL_OUTPUTS)


# ── TEST 1: mismatch corrected to match on first attempt ──────────────

def test_sc_mismatch_to_match():
    """Wrong PID (99999) -> corrector returns real PID (9001) -> MATCH."""
    wrong = {
        "finding_id": "F-INT-001",
        "artifact": "sample_payload.exe",
        "confidence_level": "HIGH",
        "claims": [
            {"type": "pid", "pid": 99999, "process": "sample_payload.exe"},
        ],
    }

    # Confirm it fails validation
    validation = validate_finding(wrong, REF_SET)
    assert validation["status"] == "MISMATCH"
    assert "99999" in validation["detail"]

    # Corrector returns finding with real PID
    fixed = {
        "finding_id": "F-INT-001",
        "artifact": "sample_payload.exe",
        "confidence_level": "HIGH",
        "claims": [
            {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
        ],
    }

    def corrector(raw_data, error):
        return copy.deepcopy(fixed)

    result = self_correct(
        finding=wrong,
        error=validation["detail"],
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=corrector,
    )

    assert result["status"] == "CORRECTED"
    assert result["self_corrected"] is True
    assert result["attempt_count"] == 1
    assert result["finding"]["claims"][0]["pid"] == 9001
    assert result["finding"]["self_corrected"] is True
    assert result["original_draft"] is wrong


# ── TEST 2: all 3 attempts fail -> UNRESOLVED ─────────────────────────

def test_sc_fails_max_attempts():
    """Corrector always returns wrong PID -> 3 attempts -> UNRESOLVED."""
    wrong = {
        "finding_id": "F-INT-002",
        "artifact": "sample_payload.exe",
        "confidence_level": "HIGH",
        "claims": [
            {"type": "pid", "pid": 99999, "process": "sample_payload.exe"},
        ],
    }

    validation = validate_finding(wrong, REF_SET)
    assert validation["status"] == "MISMATCH"

    call_count = [0]

    def always_wrong(raw_data, error):
        call_count[0] += 1
        return copy.deepcopy(wrong)

    result = self_correct(
        finding=wrong,
        error=validation["detail"],
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=always_wrong,
    )

    assert result["status"] == "UNRESOLVED"
    assert result["self_corrected"] is False
    assert call_count[0] == 3
    assert result["attempt_count"] == 3
    assert result["finding"]["confidence_level"] == "UNRESOLVED"
    assert result["finding"]["score"] == 0


# ── TEST 3: second attempt succeeds ───────────────────────────────────

def test_sc_second_attempt_succeeds():
    """Wrong hash on attempt 1, correct hash on attempt 2 -> CORRECTED."""
    wrong = {
        "finding_id": "F-INT-003",
        "artifact": "sample_payload.exe",
        "confidence_level": "HIGH",
        "claims": [
            {"type": "hash", "sha1": "0000000000000000000000000000000000000000",
             "filename": "sample_payload.exe"},
        ],
    }

    validation = validate_finding(wrong, REF_SET)
    assert validation["status"] == "MISMATCH"

    call_count = [0]
    real_sha1 = "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30"

    def fix_on_second(raw_data, error):
        call_count[0] += 1
        if call_count[0] == 1:
            # First attempt: still wrong hash
            return copy.deepcopy(wrong)
        # Second attempt: correct hash
        return {
            "finding_id": "F-INT-003",
            "artifact": "sample_payload.exe",
            "confidence_level": "HIGH",
            "claims": [
                {"type": "hash", "sha1": real_sha1, "filename": "sample_payload.exe"},
            ],
        }

    result = self_correct(
        finding=wrong,
        error=validation["detail"],
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=fix_on_second,
    )

    assert result["status"] == "CORRECTED"
    assert result["self_corrected"] is True
    assert result["attempt_count"] == 2
    assert result["finding"]["claims"][0]["sha1"] == real_sha1


# ── TEST 4: normalizer fixes field name before re-validation ──────────

def test_sc_normalizer_applied():
    """Corrector returns process_name (wrong key) -> normalizer fixes -> MATCH."""
    wrong = {
        "finding_id": "F-INT-004",
        "artifact": "sample_payload.exe",
        "confidence_level": "HIGH",
        "claims": [
            {"type": "pid", "pid": 99999, "process": "sample_payload.exe"},
        ],
    }

    validation = validate_finding(wrong, REF_SET)
    assert validation["status"] == "MISMATCH"

    # Corrector returns process_name instead of process
    def corrector(raw_data, error):
        return {
            "finding_id": "F-INT-004",
            "artifact": "sample_payload.exe",
            "confidence_level": "HIGH",
            "claims": [
                {"type": "pid", "pid": 9001, "process_name": "sample_payload.exe"},
            ],
        }

    result = self_correct(
        finding=wrong,
        error=validation["detail"],
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=corrector,
    )

    assert result["status"] == "CORRECTED"
    assert result["finding"]["claims"][0]["process"] == "sample_payload.exe"
    assert "process_name" not in result["finding"]["claims"][0]


# ── TEST 5: step 12 wiring -- 2 blocked findings, state files ─────────

def test_step_12_wiring(tmp_path):
    """Simulates Step 12: 2 blocked findings processed, results written."""
    blocked_findings = [
        {
            "finding_id": "F-WIRE-001",
            "artifact": "sample_payload.exe",
            "confidence_level": "HIGH",
            "claims": [
                {"type": "pid", "pid": 99999, "process": "sample_payload.exe"},
            ],
        },
        {
            "finding_id": "F-WIRE-002",
            "artifact": "sample_payload.exe",
            "confidence_level": "HIGH",
            "claims": [
                {"type": "hash",
                 "sha1": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                 "filename": "sample_payload.exe"},
            ],
        },
    ]

    # F-WIRE-001: corrector fixes PID
    # F-WIRE-002: corrector always returns wrong hash
    def corrector_001(raw_data, error):
        return {
            "finding_id": "F-WIRE-001",
            "artifact": "sample_payload.exe",
            "confidence_level": "HIGH",
            "claims": [
                {"type": "pid", "pid": 9001, "process": "sample_payload.exe"},
            ],
        }

    def corrector_002(raw_data, error):
        return copy.deepcopy(blocked_findings[1])

    correctors = {"F-WIRE-001": corrector_001, "F-WIRE-002": corrector_002}
    results = []

    for finding in blocked_findings:
        fid = finding["finding_id"]
        validation = validate_finding(finding, REF_SET)
        assert validation["status"] == "MISMATCH"

        sc_result = self_correct(
            finding=finding,
            error=validation["detail"],
            raw_data=RAW_DATA,
            ref_set=REF_SET,
            corrector_fn=correctors[fid],
        )
        results.append(sc_result)

        # Write state file (like coordinator Step 12 would)
        state_file = tmp_path / f"{fid}_sc.json"
        state_file.write_text(json.dumps({
            "finding_id": fid,
            "status": sc_result["status"],
            "attempt_count": sc_result["attempt_count"],
        }))

    # Verify results
    assert results[0]["status"] == "CORRECTED"
    assert results[1]["status"] == "UNRESOLVED"

    # Verify state files written
    state_001 = json.loads((tmp_path / "F-WIRE-001_sc.json").read_text())
    assert state_001["status"] == "CORRECTED"
    assert state_001["attempt_count"] == 1

    state_002 = json.loads((tmp_path / "F-WIRE-002_sc.json").read_text())
    assert state_002["status"] == "UNRESOLVED"
    assert state_002["attempt_count"] == 3
