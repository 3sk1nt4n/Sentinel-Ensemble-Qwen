"""Commit 9b: verify missing artifacts are now committed."""
import json
import os
import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_curated_docstrings_tracked():
    """src/curated_docstrings.json must be tracked in git."""
    result = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "src/curated_docstrings.json"],
        cwd=str(REPO_ROOT),
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"src/curated_docstrings.json not tracked: {result.stderr}"
    )


def test_curated_docstrings_loads_with_entries():
    """curated_docstrings.json must be valid JSON with at least 30 entries."""
    path = REPO_ROOT / "src" / "curated_docstrings.json"
    data = json.loads(path.read_text())
    assert isinstance(data, dict), f"Expected dict, got {type(data).__name__}"
    assert len(data) >= 30, f"Too few entries: {len(data)}"


def test_build_vol_help_cache_tracked():
    """scripts/build_vol_help_cache.py must be tracked in git."""
    result = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "scripts/build_vol_help_cache.py"],
        cwd=str(REPO_ROOT),
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"scripts/build_vol_help_cache.py not tracked: {result.stderr}"
    )


def test_build_script_references_vol_help_cache():
    """Generator script must mention its output file."""
    path = REPO_ROOT / "scripts" / "build_vol_help_cache.py"
    content = path.read_text()
    assert "vol_help_cache.json" in content, (
        "build_vol_help_cache.py does not reference vol_help_cache.json"
    )


def test_server_import_subprocess_silent():
    """server.py import in fresh subprocess must not warn about missing curated_docstrings.

    Uses subprocess isolation to avoid MCP re-registration side effects from
    importlib.reload. Warnings from anthropic SDK or Pydantic are allowed; only
    curated_docstrings warnings are a failure signal.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    result = subprocess.run(
        [sys.executable, "-W", "default::UserWarning", "-c",
         "import warnings; warnings.simplefilter('always'); "
         "import server; print('SERVER_IMPORT_OK')"],
        cwd=str(REPO_ROOT),
        capture_output=True, text=True,
        env=env,
        timeout=30,
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 0, (
        f"server import failed: rc={result.returncode}\n{combined}"
    )
    assert "SERVER_IMPORT_OK" in result.stdout, (
        f"server import did not complete:\n{combined}"
    )
    # Check for the specific curated_docstrings missing warning
    bad_signals = [
        "curated_docstrings.json missing or invalid",
    ]
    for signal in bad_signals:
        assert signal not in combined, (
            f"server emitted curated warning: {signal!r}\n{combined}"
        )
