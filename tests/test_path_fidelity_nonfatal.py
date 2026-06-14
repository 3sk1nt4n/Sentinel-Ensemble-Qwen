"""The pre-report PATH_FIDELITY gate must NOT discard a completed analysis. A
stale mount-alias in intermediate state files (e.g. a disk that mounted at the
legacy /mnt/windows_mount fallback when the onboarding mount failed) warns and
the run proceeds to the report by default; hard-fail is opt-in only.

Universal: env flag + boolean, no case data. Crashing after 20+ findings were
produced is never the right default for a forensic pipeline.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.path_fidelity import pre_report_should_abort  # noqa: E402


def test_gate_pass_never_aborts():
    assert pre_report_should_abort(True, env={}) is False
    assert pre_report_should_abort(True, env={"SIFT_PATH_FIDELITY_HARD": "1"}) is False


def test_gate_fail_warns_by_default():
    # DEFAULT: stale refs -> warn + continue (do NOT abort)
    assert pre_report_should_abort(False, env={}) is False


def test_gate_fail_aborts_only_in_hard_mode():
    for v in ("1", "true", "yes", "on", "TRUE"):
        assert pre_report_should_abort(False, env={"SIFT_PATH_FIDELITY_HARD": v}) is True


def test_hard_mode_off_values_do_not_abort():
    for v in ("0", "false", "no", "off", ""):
        assert pre_report_should_abort(False, env={"SIFT_PATH_FIDELITY_HARD": v}) is False
