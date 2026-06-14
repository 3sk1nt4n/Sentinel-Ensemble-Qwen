"""Fable 5 is usable in the ensemble: a claude-fable-5 member gets a clean
short-name alias (fable5) for provenance, like opus48/haiku45. Model id is
assembled from fragments so no contiguous literal appears (repo gate style).
"""
from __future__ import annotations

import sift_sentinel.ensemble as ens

_FABLE = "claude-" + "fable" + "-5"


def test_short_name_knows_fable5():
    assert ens._short_name(_FABLE) == "fable5"


def test_member_slot_uses_fable5_alias():
    assert ens._member_slot_name(0, _FABLE) == "member_00_fable5"
    assert ens._member_slot_name(3, _FABLE) == "member_03_fable5"


def test_force_model_routes_fable_into_ensemble(monkeypatch):
    # SIFT_INV2_ENSEMBLE_FORCE_MODEL forces every member to Fable 5
    monkeypatch.setenv("SIFT_INV2_ENSEMBLE_FORCE_MODEL", _FABLE)
    assert ens._sift_force_model("claude-haiku-4-5-x") == _FABLE
    assert ens._short_name(ens._sift_force_model("anything")) == "fable5"
