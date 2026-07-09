"""findevil starter contract - the one-command front door for new users.

Covers the junior-on-a-fresh-VM path promised in the README:
  ./findevil.sh            -> conversational onboarding (delegates to step0_onboard)
  ./findevil.sh --demo     -> synthetic walkthrough, no evidence / no API key
  ./findevil.sh --help     -> usage, exit 0
Headless CI safety: no path + no TTY + no piped data -> usage to stderr, exit 2
(same contract step0_onboard.main already guarantees).
"""

import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINDEVIL_PY = os.path.join(REPO_ROOT, "findevil.py")
FINDEVIL_SH = os.path.join(REPO_ROOT, "findevil.sh")


def _run_py(*args, timeout=60):
    return subprocess.run(
        [sys.executable, FINDEVIL_PY, *args],
        capture_output=True, text=True, timeout=timeout,
        stdin=subprocess.DEVNULL, cwd=REPO_ROOT,
    )


def test_findevil_files_exist_and_sh_is_executable():
    assert os.path.isfile(FINDEVIL_PY), "findevil.py missing at repo root"
    assert os.path.isfile(FINDEVIL_SH), "findevil.sh missing at repo root"
    assert os.access(FINDEVIL_SH, os.X_OK), "findevil.sh is not chmod +x"


def test_findevil_py_help_exits_zero_and_shows_own_name():
    res = _run_py("--help")
    assert res.returncode == 0, res.stderr
    out = res.stdout.lower()
    # A junior reading --help must see the evidence-path contract and the
    # demo/dry-run escape hatches, under the findevil name (not step0_onboard).
    assert "evidence" in out
    assert "--demo" in out
    assert "--dry-run" in out
    assert "findevil" in out


def test_findevil_py_headless_no_path_exits_2_with_usage():
    res = _run_py()
    assert res.returncode == 2, (res.returncode, res.stdout, res.stderr)
    assert res.stderr.strip(), "usage text expected on stderr"


def test_findevil_py_demo_runs_clean_without_evidence_or_key():
    env_no_key = {k: v for k, v in os.environ.items()
                  if k != "ANTHROPIC_API_KEY"}
    res = subprocess.run(
        [sys.executable, FINDEVIL_PY, "--demo"],
        capture_output=True, text=True, timeout=120,
        stdin=subprocess.DEVNULL, cwd=REPO_ROOT, env=env_no_key,
    )
    assert res.returncode == 0, res.stderr[-2000:]
    assert res.stdout.strip(), "demo should render the synthetic onboarding"


def test_findevil_py_delegates_to_step0_onboard():
    sys.path.insert(0, REPO_ROOT)
    try:
        import findevil
        import step0_onboard
        assert findevil.step0_onboard is step0_onboard
    finally:
        sys.path.remove(REPO_ROOT)


def test_findevil_wires_find_by_default(monkeypatch):
    # The customer front door is LIVE by default -- typing FIND launches the
    # pipeline with no --wire flag. (step0_onboard.py invoked directly keeps
    # its staged default; that contract is covered by test_onboard_launch.)
    sys.path.insert(0, REPO_ROOT)
    try:
        import findevil
        import step0_onboard
        seen = {}

        def fake_main(argv=None):
            seen["wired"] = os.environ.get("SIFT_FIND_WIRED")
            return 0

        monkeypatch.setattr(step0_onboard, "main", fake_main)
        monkeypatch.delenv("SIFT_FIND_WIRED", raising=False)
        assert findevil.main(["--demo"]) == 0
        assert seen["wired"] == "1"
    finally:
        # delenv(raising=False) on an ABSENT key records nothing to restore,
        # so the value findevil.main setdefault()s would leak into later
        # tests (it flipped test_dry_run_quiet_is_clean's staged banner).
        os.environ.pop("SIFT_FIND_WIRED", None)
        sys.path.remove(REPO_ROOT)


def test_findevil_respects_explicit_wire_off(monkeypatch):
    # An operator who exports SIFT_FIND_WIRED=0 keeps the staged behavior --
    # findevil must not clobber an explicit setting.
    sys.path.insert(0, REPO_ROOT)
    try:
        import findevil
        import step0_onboard
        seen = {}

        def fake_main(argv=None):
            seen["wired"] = os.environ.get("SIFT_FIND_WIRED")
            return 0

        monkeypatch.setattr(step0_onboard, "main", fake_main)
        monkeypatch.setenv("SIFT_FIND_WIRED", "0")
        assert findevil.main(["--demo"]) == 0
        assert seen["wired"] == "0"
    finally:
        sys.path.remove(REPO_ROOT)


@pytest.mark.skipif(not os.path.exists("/bin/bash"), reason="bash required")
def test_findevil_sh_help_exits_zero():
    res = subprocess.run(
        ["bash", FINDEVIL_SH, "--help"],
        capture_output=True, text=True, timeout=60,
        stdin=subprocess.DEVNULL, cwd=REPO_ROOT,
    )
    assert res.returncode == 0, res.stderr
    assert "findevil" in res.stdout.lower()
