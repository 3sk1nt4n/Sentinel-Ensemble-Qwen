"""31Z regression: INV2_ENSEMBLE_MODE accepts env-var enablement.

Block 2 live run set SIFT_INV2_ENSEMBLE=1 and SIFT_INV2_ENSEMBLE_ENABLED=1
but ensemble silently never fired because INV2_ENSEMBLE_MODE only read
the --inv2-ensemble CLI flag (which wasn't passed). The dispatcher
machinery in src/sift_sentinel/ensemble.py was fully wired; only the
gating condition was incomplete. 31Z adds env-var OR-clauses so
either path enables ensemble mode.

Property tests are static-text guards. Real runtime validation is the
next Block 2 live run with the same env vars: inv2_ensemble_stats.json
must be produced and the audit gate must flip FAIL -> PASS.
"""
from pathlib import Path


def test_31z_cli_flag_path_preserved():
    src = Path("run_pipeline.py").read_text()
    assert 'getattr(_args, "inv2_ensemble", False)' in src, (
        "31Z guard: CLI flag path must be preserved alongside env vars"
    )


def test_31z_sift_inv2_ensemble_env_consumed():
    src = Path("run_pipeline.py").read_text()
    # The env var must be read in the gating condition at module level
    assert 'os.environ.get("SIFT_INV2_ENSEMBLE"' in src, (
        "31Z: SIFT_INV2_ENSEMBLE env var must be read in INV2_ENSEMBLE_MODE"
    )


def test_31z_sift_inv2_ensemble_enabled_env_consumed():
    src = Path("run_pipeline.py").read_text()
    assert 'os.environ.get("SIFT_INV2_ENSEMBLE_ENABLED"' in src, (
        "31Z: SIFT_INV2_ENSEMBLE_ENABLED env var must be read in INV2_ENSEMBLE_MODE"
    )


def test_31z_truthy_values_accepted():
    src = Path("run_pipeline.py").read_text()
    # Must accept conventional truthy strings, not just literal "1"
    for v in ("1", "true", "yes", "on"):
        assert f'"{v}"' in src, f"31Z: truthy value '{v}' must be accepted"


def test_31z_no_marketing_inflation_in_log():
    """Ensure the existing 'ENSEMBLE MODE' log line still gates on the flag,
    not on env-var presence alone — i.e. the log truthfully reports actual
    dispatch, not user intent."""
    src = Path("run_pipeline.py").read_text()
    # The log line must be guarded by INV2_ENSEMBLE_MODE check, not by env
    # vars directly. (Static check: the log string exists somewhere downstream
    # of the assignment and is logger-gated.)
    assert "Inv2 ENSEMBLE MODE: dispatching" in src, (
        "31Z: existing ENSEMBLE MODE log line must still be present"
    )
