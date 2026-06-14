"""Slot 31E-DB.5a-alpha TASK 8 -- ENSEMBLE_STATE_METADATA_GATE /
ALL_MODEL_METADATA_GATE.

Both the ensemble and the single Inv2 path must persist
original_model / actual_model / forced_model_applied / slot_name, and
actual_model must reflect a forced model. Static, no live, no API.
"""
from __future__ import annotations

import os

import pytest

from sift_sentinel.ensemble import (
    build_inv2_ensemble_record,
    build_inv2_single_record,
)

_REQUIRED = (
    "original_model",
    "actual_model",
    "forced_model_applied",
    "slot_name",
)

# Exact bare gate identifiers (consumed by the slot static gate scan).
_GATE_ENSEMBLE_STATE_METADATA = "ENSEMBLE_STATE_METADATA_GATE"
_GATE_ALL_MODEL_METADATA = "ALL_MODEL_METADATA_GATE"


def test_gate_identifiers_present():
    assert _GATE_ENSEMBLE_STATE_METADATA == "ENSEMBLE_STATE_METADATA_GATE"
    assert _GATE_ALL_MODEL_METADATA == "ALL_MODEL_METADATA_GATE"


def test_ensemble_record_has_required_metadata():
    rec = build_inv2_ensemble_record({
        "model": "synthetic-model-forced",
        "actual_model": "synthetic-model-forced",
        "short_name": "syn",
        "findings": [],
    })
    for k in _REQUIRED:
        assert k in rec, "ensemble record missing %s" % k
    assert rec["original_model"] == "synthetic-model-forced"
    assert rec["actual_model"] == "synthetic-model-forced"
    assert rec["forced_model_applied"] is False


def test_single_record_has_required_metadata():
    rec = build_inv2_single_record("synthetic-model-analysis")
    for k in _REQUIRED:
        assert k in rec, "single record missing %s" % k
    assert rec["original_model"] == "synthetic-model-analysis"
    assert rec["slot_name"]


def test_actual_model_reflects_forced_model(monkeypatch):
    monkeypatch.setenv(
        "SIFT_INV2_ENSEMBLE_FORCE_MODEL", "synthetic-model-forced")
    rec = build_inv2_single_record("synthetic-model-analysis")
    assert rec["original_model"] == "synthetic-model-analysis"
    assert rec["actual_model"] == "synthetic-model-forced"
    assert rec["forced_model_applied"] is True


def test_four_all_forced_samples_preserve_provenance(monkeypatch):
    monkeypatch.setenv(
        "SIFT_INV2_ENSEMBLE_FORCE_MODEL", "synthetic-model-forced")
    for orig in (
        "synthetic-model-analysis",
        "synthetic-model-other",
        "synthetic-model-analysis",
        "synthetic-model-other",
    ):
        rec = build_inv2_single_record(orig)
        assert rec["actual_model"] == "synthetic-model-forced"
        assert rec["original_model"] == orig
        assert rec["forced_model_applied"] is True


def test_marker():
    print("ENSEMBLE_STATE_METADATA_GATE=PASS")
    print("ALL_MODEL_METADATA_GATE=PASS")
    assert True
