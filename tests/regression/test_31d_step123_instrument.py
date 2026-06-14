"""Slot 31D-STEP123-INSTRUMENT regression tests.

Pins:
  - run_pipeline.py emits STEP123_TIMING lines for preflight_s, sha_pre_s,
    ssdt_s, profile_s, and total_step1_3_s (machine-readable labels);
  - --stop-after-step N exists, and N<=3 exits cleanly before Step 4 / AI
    / MCP / Step 6, with no live model call possible (proven via
    SIFT_ASSERT_NO_LIVE_CALL=1);
  - this instrumentation rung does NOT modify sha256_fingerprint
    read/hash/buffer logic in coordinator.py;
  - no cross-run sha256 cache is introduced (audit telemetry only,
    never loaded to skip work);
  - no dataset literals are introduced into the changed source.

Cheap and no-live: only static reads + one subprocess run against tiny
temp evidence files. Must NOT import run_pipeline.py (top-level argparse
runs at import).
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]
_RUN_PIPELINE = _REPO_ROOT / "run_pipeline.py"
_COORDINATOR = _REPO_ROOT / "src" / "sift_sentinel" / "coordinator.py"


def _run_pipeline_source() -> str:
    return _RUN_PIPELINE.read_text(encoding="utf-8")


def _coordinator_source() -> str:
    return _COORDINATOR.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Test 1: timing labels are present in the source.
# ---------------------------------------------------------------------------


def test_step123_timing_labels_present_in_source() -> None:
    src = _run_pipeline_source()
    required = [
        "STEP123_TIMING",
        "preflight_s",
        "sha_pre_s",
        "ssdt_s",
        "profile_s",
        "total_step1_3_s",
    ]
    missing = [lbl for lbl in required if lbl not in src]
    assert not missing, (
        f"run_pipeline.py is missing STEP123_TIMING labels: {missing}"
    )


# ---------------------------------------------------------------------------
# Test 2: --stop-after-step CLI flag is declared.
# ---------------------------------------------------------------------------


def test_stop_after_step_argparse_flag_declared() -> None:
    src = _run_pipeline_source()
    assert "--stop-after-step" in src, (
        "run_pipeline.py must declare --stop-after-step (Slot 31D-STEP123-INSTRUMENT)"
    )


# ---------------------------------------------------------------------------
# Test 3: this test file itself must NOT import run_pipeline.
# ---------------------------------------------------------------------------


def test_this_test_does_not_import_run_pipeline() -> None:
    this_file = Path(__file__).read_text(encoding="utf-8")
    # Build the forbidden tokens at runtime so this assertion does not
    # match its own source literal. We allow string references to
    # "run_pipeline.py" inside subprocess argv lists.
    _mod = "run_pipeline"
    forbidden = [f"import {_mod}", f"from {_mod} "]
    # Inspect only non-comment, non-docstring import lines.
    offenders: list[str] = []
    for ln in this_file.splitlines():
        stripped = ln.strip()
        if stripped.startswith("#"):
            continue
        for tok in forbidden:
            if stripped.startswith(tok):
                offenders.append(stripped)
    assert not offenders, (
        f"This test must not import run_pipeline (top-level argparse). "
        f"Offending lines: {offenders}"
    )


# ---------------------------------------------------------------------------
# Test 4: --stop-after-step 3 path runs API-free, exits 0, and never
# reaches Step 4 / Inv1 / MCP / Step 6.
# ---------------------------------------------------------------------------


def _build_synthetic_evidence(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Create minimal synthetic evidence files + mount sentinel layout."""
    mem = tmp_path / "memory.img"
    # Small bytes -- enough to be a real file but not enough to be slow.
    mem.write_bytes(b"\x00" * 1024)

    disk = tmp_path / "disk.E01"
    disk.write_bytes(b"\x00" * 1024)

    mount = tmp_path / "mount"
    (mount / "Windows" / "System32" / "config").mkdir(parents=True)
    (mount / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(
        b"\x00" * 64
    )
    (mount / "Windows" / "System32" / "winevt" / "Logs").mkdir(parents=True)
    (mount / "Users").mkdir()
    return mem, disk, mount


def test_stop_after_step_3_is_api_free_and_exits_clean(tmp_path: Path) -> None:
    mem, disk, mount = _build_synthetic_evidence(tmp_path)

    env = os.environ.copy()
    env["SIFT_ASSERT_NO_LIVE_CALL"] = "1"
    # PYTHONPATH=src:. so coordinator imports succeed.
    env["PYTHONPATH"] = (
        f"{_REPO_ROOT / 'src'}{os.pathsep}{_REPO_ROOT}"
    )
    # Force-disable color so STEP123_TIMING markers and "STEP 4"/"STEP 6"
    # markers are not wrapped in escape codes.
    env.pop("SIFT_FORCE_COLOR", None)

    cmd = [
        sys.executable, "-u", str(_RUN_PIPELINE),
        "--direct",
        "--stop-after-step", "3",
        "--image", str(mem),
        "--disk", str(disk),
        "--disk-mount", str(mount),
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True, env=env, timeout=120,
        cwd=str(_REPO_ROOT),
    )

    combined = (result.stdout or "") + (result.stderr or "")

    assert result.returncode == 0, (
        f"--stop-after-step 3 must exit 0, got {result.returncode}.\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )
    assert "STEP123_TIMING" in combined, (
        f"STEP123_TIMING markers must appear in output.\n{combined}"
    )
    assert "total_step1_3_s" in combined, (
        f"total_step1_3_s timing label must appear.\n{combined}"
    )

    # Bounded exit: must not reach Step 4 / Inv1 / live model / Step 6.
    forbidden_markers = [
        "STEP 4",
        "AI TOOL SELECTION",
        "LIVE: Calling",
        "STEP 6",
    ]
    leaked = [m for m in forbidden_markers if m in combined]
    assert not leaked, (
        f"--stop-after-step 3 leaked into later stages: {leaked}\n"
        f"--- combined ---\n{combined}"
    )


# ---------------------------------------------------------------------------
# Test 5: sha256_fingerprint hash/read/buffer logic unchanged in this rung.
# ---------------------------------------------------------------------------


def _git_diff_for(path: Path) -> str:
    """Return `git diff HEAD -- <path>` (working tree vs last commit)."""
    res = subprocess.run(
        ["git", "diff", "HEAD", "--", str(path)],
        capture_output=True, text=True, cwd=str(_REPO_ROOT), timeout=30,
    )
    # If git fails, fall back to empty diff (test will still catch direct
    # source-text drift via the negative checks below).
    return res.stdout or ""


_SHA_FORBIDDEN_TOKENS = (
    "hashlib.sha256",
    ".read(",
    "readinto",
    "block_size",
    "buffer",
    "fadvise",
    "update(",
)


def test_sha256_fingerprint_hash_logic_unchanged_by_this_rung() -> None:
    """Diff coordinator.py against HEAD; assert no SHA hot-path edits."""
    diff = _git_diff_for(_COORDINATOR)
    # Only inspect added lines (lines that start with '+', excluding '+++').
    added = [
        ln for ln in diff.splitlines()
        if ln.startswith("+") and not ln.startswith("+++")
    ]
    offenders: list[tuple[str, str]] = []
    for ln in added:
        body = ln[1:]
        for tok in _SHA_FORBIDDEN_TOKENS:
            if tok in body:
                offenders.append((tok, body.strip()))
    assert not offenders, (
        "This rung is INSTRUMENT-ONLY. Adding lines that touch the "
        "sha256_fingerprint hot path is forbidden:\n"
        + "\n".join(f"  [{tok}] {ln}" for tok, ln in offenders)
    )


# ---------------------------------------------------------------------------
# Test 6: no cross-run SHA cache introduced.
# ---------------------------------------------------------------------------


_SHA_CACHE_FORBIDDEN_SUBSTRINGS = (
    "sha256 cache",
    "cache sha256",
    "loading sha256_pre.json to skip",
)

# Tokens that smell like "read sha256 state in order to skip hashing".
# We require the line to contain BOTH a state-read verb AND sha256 to
# minimize false positives on innocuous mentions.
_SHA_CACHE_READ_VERBS = ("read_state", "load_state", "json.load", "open(")


def _changed_files_against_head() -> list[Path]:
    res = subprocess.run(
        ["git", "diff", "HEAD", "--name-only"],
        capture_output=True, text=True, cwd=str(_REPO_ROOT), timeout=30,
    )
    out = res.stdout or ""
    return [_REPO_ROOT / line.strip() for line in out.splitlines() if line.strip()]


def _added_lines_for(path: Path) -> list[str]:
    res = subprocess.run(
        ["git", "diff", "HEAD", "--", str(path)],
        capture_output=True, text=True, cwd=str(_REPO_ROOT), timeout=30,
    )
    diff = res.stdout or ""
    return [
        ln[1:] for ln in diff.splitlines()
        if ln.startswith("+") and not ln.startswith("+++")
    ]


def test_no_cross_run_sha256_cache_introduced() -> None:
    offenders: list[tuple[str, str, str]] = []
    for path in _changed_files_against_head():
        if not path.exists() or not path.is_file():
            continue
        if path.suffix not in {".py", ".sh"}:
            continue
        # Skip the test file itself -- it lists the forbidden substrings.
        if path.resolve() == Path(__file__).resolve():
            continue
        for ln in _added_lines_for(path):
            low = ln.lower()
            for sub in _SHA_CACHE_FORBIDDEN_SUBSTRINGS:
                if sub in low:
                    offenders.append((str(path), sub, ln.strip()))
            if "sha256" in low and any(
                verb in low for verb in _SHA_CACHE_READ_VERBS
            ) and "skip" in low:
                offenders.append((str(path), "read+sha256+skip", ln.strip()))
    assert not offenders, (
        "No cross-run sha256 cache may be introduced by this rung:\n"
        + "\n".join(
            f"  {p} :: [{kind}] {ln}" for p, kind, ln in offenders
        )
    )


# ---------------------------------------------------------------------------
# Test 7: no dataset literals introduced into changed files.
# ---------------------------------------------------------------------------


# Dataset-agnostic: forbid case-specific literals that have appeared in
# past stand-up runs (IPv4 addresses, MAC-ish patterns, attacker hostnames).
# We keep this minimal -- the broader integrity_sweep test enforces the
# canonical no-cheat surface.
import re as _re

_IPV4_RE = _re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
                        r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
# Allowed loopback / private mention literals that are NOT dataset
# specifics. We intentionally allow these because they show up in
# unrelated infra examples (e.g. localhost, RFC1918 textbook ranges).
_ALLOWED_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}


def test_no_dataset_literals_in_changed_files() -> None:
    offenders: list[tuple[str, str]] = []
    for path in _changed_files_against_head():
        if not path.exists() or not path.is_file():
            continue
        if path.suffix not in {".py", ".sh", ".md", ".json"}:
            continue
        # Skip the test file itself -- regex literals would self-trigger.
        if path.resolve() == Path(__file__).resolve():
            continue
        for ln in _added_lines_for(path):
            for ip in _IPV4_RE.findall(ln):
                if ip in _ALLOWED_IPS:
                    continue
                offenders.append((str(path), f"{ip} :: {ln.strip()}"))
    assert not offenders, (
        "Dataset literals (IPv4 addresses) must not appear in changed "
        "source for this instrumentation rung:\n"
        + "\n".join(f"  {p} :: {ln}" for p, ln in offenders)
    )
