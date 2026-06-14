"""Step6 old-commit compatibility guard.

This commit does not necessarily have the newer all-submitted/as_completed
Step6 architecture. The speed tweak here is intentionally small:
- default Step6 workers become 14 where the branch has the worker env hook
- SIFT_STEP6_MAX_WORKERS remains the override path, so 16 can be tested live
- no blocking heavy-gate vocabulary should be introduced
- no dataset literals, case keys, or cache shortcuts
"""

from pathlib import Path
import re


def test_step6_worker_env_hook_present_and_default_is_14_when_present():
    src = Path("run_pipeline.py").read_text(errors="replace")

    assert "SIFT_STEP6_MAX_WORKERS" in src

    default_14_patterns = [
        r'get\("SIFT_STEP6_MAX_WORKERS",\s*"14"\)',
        r"get\('SIFT_STEP6_MAX_WORKERS',\s*'14'\)",
        r'getenv\("SIFT_STEP6_MAX_WORKERS",\s*"14"\)',
        r"getenv\('SIFT_STEP6_MAX_WORKERS',\s*'14'\)",
    ]
    assert any(re.search(pat, src) for pat in default_14_patterns), (
        "SIFT_STEP6_MAX_WORKERS exists, but default is not 14"
    )


def test_step6_does_not_introduce_blocking_heavy_gate():
    src = Path("run_pipeline.py").read_text(errors="replace")

    assert "Step6 HEAVY_GATE" not in src
    assert "_gate_futs" not in src
    assert "SIFT_STEP6_HEAVY_GATE_S" not in src
    assert "as_completed(list(_gate_futs.keys())" not in src


def test_newer_branch_architecture_is_not_required_on_this_commit():
    src = Path("run_pipeline.py").read_text(errors="replace")

    # This old commit may not have the newer all-submitted / _future_map
    # Step6 architecture. Do not require it here. This test is intentionally
    # scoped to the small worker-count speed tweak.
    assert "SIFT_STEP6_MAX_WORKERS" in src


def test_no_dataset_literals_in_this_test():
    text = Path(__file__).read_text(errors="replace")
    banned = [
        "base-" + "rd01",
        "rd-" + "01",
        "td" + "ungan",
        "sp" + "sql",
        "172." + "16.",
        "Wmi" + "PrvSE",
        "OUT" + "LOOK",
        "p." + "exe",
    ]
    for token in banned:
        assert token not in text
