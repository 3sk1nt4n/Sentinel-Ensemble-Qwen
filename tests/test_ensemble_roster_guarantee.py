"""An onboarded ensemble run must never die at Step 8 on an unconfigured roster: the
launcher synthesises SIFT_ENSEMBLE_MODELS from the chosen model when the operator
hasn't set one. The mode still forces which model runs; the roster only sets the
member count. Universal: no model literal -- the id comes from the mode.
"""
import step0_onboard as s


def _mode(model="prov-model-x", ensemble=True):
    return {"key": "heavy", "model": model, "ensemble": ensemble,
            "name": "n", "label": "l", "icon": "i", "cost": "$"}


def test_roster_synthesised_from_chosen_model_when_unset():
    env = {}  # no SIFT_ENSEMBLE_MODELS exported
    delta = s.ensemble_roster_env(_mode("prov-model-x"), env)
    roster = delta["SIFT_ENSEMBLE_MODELS"].split(",")
    assert roster == ["prov-model-x"] * 4          # default 4-member roster
    assert all(m == "prov-model-x" for m in roster)


def test_explicit_operator_roster_is_never_overridden():
    env = {"SIFT_ENSEMBLE_MODELS": "a,b,c"}
    assert s.ensemble_roster_env(_mode(), env) == {}


def test_non_ensemble_mode_adds_nothing():
    assert s.ensemble_roster_env(_mode(ensemble=False), {}) == {}


def test_empty_model_adds_nothing():
    assert s.ensemble_roster_env(_mode(model=""), {}) == {}


def test_size_is_configurable(monkeypatch):
    monkeypatch.setenv("SIFT_ENSEMBLE_SIZE", "3")
    delta = s.ensemble_roster_env(_mode("m"), {})
    assert delta["SIFT_ENSEMBLE_MODELS"].split(",") == ["m", "m", "m"]


def test_bad_size_falls_back_to_four(monkeypatch):
    monkeypatch.setenv("SIFT_ENSEMBLE_SIZE", "not-a-number")
    delta = s.ensemble_roster_env(_mode("m"), {})
    assert len(delta["SIFT_ENSEMBLE_MODELS"].split(",")) == 4


def test_size_clamped_to_sane_range(monkeypatch):
    monkeypatch.setenv("SIFT_ENSEMBLE_SIZE", "999")
    delta = s.ensemble_roster_env(_mode("m"), {})
    assert len(delta["SIFT_ENSEMBLE_MODELS"].split(",")) == 4   # out-of-range -> default
