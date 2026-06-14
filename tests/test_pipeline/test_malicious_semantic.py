"""Slot 31E-DB.5.4 -- malicious semantic signal registry / gate.

Dataset-agnostic. No API key, no live run, no network. Every registered
signal must own a callable matcher and a positive fixture; no skip is
permitted for a missing fixture.
"""

from __future__ import annotations

import json
from pathlib import Path

from sift_sentinel.analysis.disposition import (
    BUCKET_BENIGN,
    BUCKET_CONFIRMED,
    BUCKET_SUSPICIOUS,
    derive_final_disposition,
    evaluate_confirmed_bucket_eligibility,
)
from sift_sentinel.analysis.malicious_semantics import (
    ENVIRONMENT_CONTEXT_SIGNALS,
    LEGITIMATE_NULL_CMDLINE_PROCESSES,
    MALICIOUS_SEMANTIC_SIGNALS,
    has_malicious_semantic,
)

_FIXTURES = Path(__file__).resolve().parents[1] / (
    "fixtures/malicious_semantic")


def test_registry_structure_minimums():
    assert len(MALICIOUS_SEMANTIC_SIGNALS) >= 8
    assert len(ENVIRONMENT_CONTEXT_SIGNALS) >= 6
    assert len(LEGITIMATE_NULL_CMDLINE_PROCESSES) >= 3
    for name, spec in MALICIOUS_SEMANTIC_SIGNALS.items():
        assert spec.get("required_fact_types"), name
        assert spec.get("description"), name
        assert callable(spec.get("matcher")), name


def test_each_malicious_semantic_matcher_fires_on_positive_fixture():
    for name, spec in MALICIOUS_SEMANTIC_SIGNALS.items():
        path = _FIXTURES / ("%s_positive.json" % name)
        # No skip allowed: a missing positive fixture is a hard failure.
        assert path.exists(), "missing positive fixture: %s" % path
        payload = json.loads(path.read_text())
        fact = payload.get("fact", payload)
        evidence_db = payload.get("evidence_db")
        matcher = spec["matcher"]
        assert callable(matcher), name
        assert matcher(fact, evidence_db=evidence_db) is True, (
            "%s matcher did not fire on its positive fixture" % name
        )


def test_f005_environment_context_only_cannot_confirm():
    f005 = {
        "finding_id": "F005_regression",
        "title": "synthetic environment context regression fixture",
        "severity": "HIGH",
        "confidence_level": "HIGH",
        "source_tools": ["parse_event_logs"],
        "tool_call_ids": ["c"],
        "raw_excerpt": "Synthetic MsiInstaller event fixture",
        "claims": [{"type": "event_log_fact", "value": "synthetic"}],
        "post_sc": True,
        "malicious_semantic_signals": [],
        "environment_context_signals": ["msi_installer_event"],
    }
    res = evaluate_confirmed_bucket_eligibility(f005)
    assert res["eligible"] is False
    assert res["gates"]["MALICIOUS_SEMANTIC_GATE"] == "FAIL"
    bucket, _ = derive_final_disposition(f005)
    assert bucket in (BUCKET_SUSPICIOUS, BUCKET_BENIGN)


def test_post_sc_does_not_bypass_semantic_gate():
    f = {
        "finding_id": "Fpsc",
        "title": "synthetic",
        "severity": "HIGH",
        "confidence_level": "HIGH",
        "source_tools": ["parse_event_logs"],
        "tool_call_ids": ["c"],
        "raw_excerpt": "benign service listening",
        "claims": [{"type": "event_log_fact", "value": "s"}],
        "post_sc": True,
        "environment_context_signals": ["service_listening_port_only"],
        "malicious_semantic_signals": [],
    }
    res = evaluate_confirmed_bucket_eligibility(f)
    assert res["eligible"] is False
    assert res["gates"]["MALICIOUS_SEMANTIC_GATE"] == "FAIL"


def test_malicious_signal_plus_evidence_can_confirm():
    f = {
        "finding_id": "Fgood",
        "title": "Suspicious executable staged in temp directory",
        "severity": "HIGH",
        "confidence_level": "HIGH",
        "source_tools": ["get_amcache", "vol_pstree"],
        "tool_call_ids": ["get_amcache", "vol_pstree"],
        "raw_excerpt": (
            "path:C:\\Windows\\Temp\\perfmon\\tool.exe, sha1:deadbeef"
        ),
        "claims": [
            {"type": "hash", "sha1": "deadbeef", "filename": "tool.exe"},
            {"type": "path", "value": "C:\\Windows\\Temp\\perfmon"},
        ],
        "validator_metadata": {
            "typed_fact_refs": [
                {"fact_type": "file_execution_fact"},
                {"fact_type": "process_fact"},
            ],
            "source_tools": ["get_amcache", "vol_pstree"],
        },
    }
    has_sem, sigs = has_malicious_semantic(f)
    assert has_sem is True
    assert "executes_from_temp_path" in sigs
    res = evaluate_confirmed_bucket_eligibility(f)
    assert res["eligible"] is True
    bucket, _ = derive_final_disposition(f)
    assert bucket == BUCKET_CONFIRMED


def test_environment_context_signals_alone_cannot_confirm():
    f = {
        "finding_id": "Fenv",
        "title": "process exists",
        "severity": "HIGH",
        "confidence_level": "HIGH",
        "source_tools": ["vol_pstree"],
        "tool_call_ids": ["vol_pstree"],
        "raw_excerpt": "PID:1234 Process:notepad.exe",
        "claims": [{"type": "process_exists", "pid": 1234}],
        "environment_context_signals": ["process_exists"],
    }
    has_sem, _ = has_malicious_semantic(f)
    assert has_sem is False
    assert evaluate_confirmed_bucket_eligibility(f)["eligible"] is False


def test_legitimate_null_cmdline_process_is_not_malicious():
    fact = {"type": "process_fact", "process": "System", "cmdline": None}
    from sift_sentinel.analysis.malicious_semantics import (
        match_null_or_empty_cmdline_on_executable as m,
    )
    assert m(fact) is False
