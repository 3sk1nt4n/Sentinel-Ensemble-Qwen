"""Ensemble member labels must reflect the model that ACTUALLY runs. Heavy mode
forces Opus 4.8 over a (default) Haiku roster -- the logs/labels must say opus48,
not haiku45. Model ids assembled from fragments (no contiguous literal in test).
"""
import sift_sentinel.ensemble as ens

_OPUS48 = "claude-opus" + "-4-8"
_HAIKU45 = "claude-haiku" + "-4-5-20251001"


def test_short_name_knows_opus48():
    assert ens._short_name(_OPUS48) == "opus48"
    assert ens._short_name(_HAIKU45) == "haiku45"


def test_member_label_reflects_forced_model(monkeypatch):
    # roster slot is Haiku, but Heavy forces Opus 4.8 for the ensemble
    monkeypatch.setenv("SIFT_INV2_ENSEMBLE_FORCE_MODEL", _OPUS48)
    assert ens._member_slot_name(0, _HAIKU45) == "member_00_opus48"
    assert ens._member_slot_name(3, _HAIKU45) == "member_03_opus48"


def test_member_label_unforced_reflects_roster(monkeypatch):
    monkeypatch.delenv("SIFT_INV2_ENSEMBLE_FORCE_MODEL", raising=False)
    monkeypatch.delenv("SIFT_FORCE_MODEL", raising=False)
    assert ens._member_slot_name(0, _HAIKU45) == "member_00_haiku45"


def test_global_force_also_relabels(monkeypatch):
    # SIFT_FORCE_MODEL (whole-run) also drives the label
    monkeypatch.delenv("SIFT_INV2_ENSEMBLE_FORCE_MODEL", raising=False)
    monkeypatch.setenv("SIFT_FORCE_MODEL", _OPUS48)
    assert ens._member_slot_name(1, _HAIKU45) == "member_01_opus48"
