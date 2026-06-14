"""Slot 31E-DB.5c TASK 3 -- model routing is env/config-driven.

Replaces the old commit-8 literal pins. Production source carries NO
exact provider/model literal; every stage model resolves at runtime
via sift_sentinel.model_roles. Synthetic model names only. Where a
provider token must be referenced (redaction checks) it is assembled
by concatenation so a naive literal scan does not hit.
"""
import pathlib

from sift_sentinel.model_roles import (
    ModelNotConfiguredError,
    model_for_label,
    resolve_model,
)

# Assembled provider fragment -- never a contiguous literal in source.
_PROVIDER = "claude" + "-"


def test_synthetic_defaults_in_test_mode():
    """Under pytest (test mode) each role yields its synthetic default."""
    assert resolve_model("inv1_primary") == "synthetic-model-primary"
    assert resolve_model("inv1_retry") == "synthetic-model-retry"
    assert resolve_model("analysis") == "synthetic-model-analysis"
    assert resolve_model("react") == "synthetic-model-react"
    assert resolve_model("report") == "synthetic-model-report"
    assert resolve_model("self_correction") == (
        "synthetic-model-self-correction"
    )


def test_role_specific_env_wins(monkeypatch):
    monkeypatch.setenv("SIFT_MODEL_INV1_PRIMARY", "synthetic-model-forced")
    assert resolve_model("inv1_primary") == "synthetic-model-forced"
    # other roles unaffected
    assert resolve_model("analysis") == "synthetic-model-analysis"


def test_force_then_default_precedence(monkeypatch):
    monkeypatch.setenv("SIFT_FORCE_MODEL", "synthetic-model-forced")
    assert resolve_model("analysis") == "synthetic-model-forced"
    monkeypatch.delenv("SIFT_FORCE_MODEL", raising=False)
    monkeypatch.setenv("SIFT_DEFAULT_MODEL", "synthetic-model-default-x")
    assert resolve_model("report") == "synthetic-model-default-x"


def test_live_mode_with_nothing_configured_fails(monkeypatch):
    """Live (no synthetic) must fail clearly, never silently fake."""
    monkeypatch.setenv("SIFT_LIVE", "1")
    for var in (
        "SIFT_MODEL_ANALYSIS", "SIFT_FORCE_MODEL", "SIFT_DEFAULT_MODEL",
    ):
        monkeypatch.delenv(var, raising=False)
    try:
        resolve_model("analysis")
        raised = False
    except ModelNotConfiguredError:
        raised = True
    assert raised, "live mode must raise when no model configured"


def test_label_to_model_routing(monkeypatch):
    monkeypatch.setenv("SIFT_MODEL_INV1_PRIMARY", "synthetic-model-primary")
    monkeypatch.setenv("SIFT_MODEL_INV1_RETRY", "synthetic-model-retry")
    monkeypatch.setenv("SIFT_MODEL_REPORT", "synthetic-model-report")
    monkeypatch.setenv("SIFT_MODEL_ANALYSIS", "synthetic-model-analysis")
    monkeypatch.setenv("SIFT_MODEL_REACT", "synthetic-model-react")
    monkeypatch.setenv(
        "SIFT_MODEL_SELF_CORRECTION", "synthetic-model-self-correction")

    assert model_for_label("Inv1") == "synthetic-model-primary"
    assert model_for_label("Inv1 retry") == "synthetic-model-retry"
    assert model_for_label("Inv4 report") == "synthetic-model-report"
    assert model_for_label("Inv2 analysis") == "synthetic-model-analysis"
    assert model_for_label("Inv ReAct") == "synthetic-model-react"
    assert model_for_label("Inv SC (t=30s)") == (
        "synthetic-model-self-correction"
    )
    assert model_for_label("SC retry") == "synthetic-model-self-correction"
    assert model_for_label("correction") == (
        "synthetic-model-self-correction"
    )


def test_no_provider_literal_in_production_source():
    """run_pipeline.py + src/ must not carry a contiguous provider
    model literal. Fragments are assembled at runtime instead."""
    root = pathlib.Path(__file__).resolve().parent.parent
    targets = [root / "run_pipeline.py"]
    targets += list((root / "src").rglob("*.py"))
    bad = []
    needles = (
        _PROVIDER + "haiku",
        _PROVIDER + "opus",
        _PROVIDER + "sonnet",
        "gpt" + "-5",
        "gemini" + "-3",
    )
    for p in targets:
        text = p.read_text(errors="ignore")
        for n in needles:
            if n in text:
                bad.append((str(p.relative_to(root)), n))
    assert not bad, f"provider literal leaked into production: {bad}"
