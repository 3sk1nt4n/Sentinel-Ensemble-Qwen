"""Slot 31D-STEP123-SINGLE-SHA-HANDOFF V2 regression tests.

Pins:
  - coordinator.step_02_fingerprint accepts a precomputed-hashes
    parameter so the canonical full pre-run SHA pass happens once;
  - valid precomputed hashes are reused without re-hashing;
  - invalid / sentinel precomputed hashes fall back honestly;
  - no new cross-run on-disk SHA cache (.evidence_hash / sha256_pre.json
    must NOT be loaded to skip hashing);
  - SHA read/buffer/hash-loop logic is unchanged by this rung;
  - --stop-after-step 3 still exits cleanly with STEP123_TIMING markers
    and never touches Step 4 / AI / Step 6, with SIFT_ASSERT_NO_LIVE_CALL=1;
  - no dataset literals introduced.

Cheap and no-live: static reads + a small subprocess. Must NOT import
run_pipeline (top-level argparse executes at import).
"""
from __future__ import annotations

import inspect
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import sift_sentinel.coordinator as coord


_REPO_ROOT = Path(__file__).resolve().parents[2]
_RUN_PIPELINE = _REPO_ROOT / "run_pipeline.py"
_COORDINATOR = _REPO_ROOT / "src" / "sift_sentinel" / "coordinator.py"


# ---------------------------------------------------------------------------
# Test 1: step_02_fingerprint accepts a precomputed-hashes kwarg.
# ---------------------------------------------------------------------------


def test_step_02_fingerprint_accepts_precomputed_hashes_kwarg() -> None:
    sig = inspect.signature(coord.step_02_fingerprint)
    # Accept either the preferred name "precomputed_hashes" or a clear
    # equivalent ("pre_hashes" / "hashes"). Preferred is asserted in the
    # next test by passing it explicitly as a keyword argument.
    params = set(sig.parameters.keys())
    candidates = {"precomputed_hashes", "pre_hashes", "hashes"}
    assert params & candidates, (
        f"step_02_fingerprint must accept a precomputed-hashes kwarg "
        f"(one of {candidates}); got params={params}"
    )


# ---------------------------------------------------------------------------
# Test 2: valid precomputed hashes -> no recompute (no sha256_fingerprint call).
# ---------------------------------------------------------------------------


def test_step_02_fingerprint_reuses_precomputed_no_recompute(
    monkeypatch, tmp_path: Path,
) -> None:
    """Monkeypatch coord.sha256_fingerprint to raise.

    If step_02_fingerprint still calls it when valid precomputed hashes
    are supplied, the test fails -- proving no recompute happens.
    """
    state_dir = tmp_path / "state"

    # Create one tiny real evidence file so the path actually exists.
    ev = tmp_path / "evidence.bin"
    ev.write_bytes(b"\x00" * 16)
    paths = [str(ev)]
    valid_hashes = {
        # Real or synthetic hex is fine; reuse path means we never hash.
        str(ev): "deadbeefcafef00d" * 4,
    }

    def _explode(*_args, **_kwargs):  # pragma: no cover - intentional fail
        raise AssertionError(
            "sha256_fingerprint was called despite valid precomputed_hashes"
        )

    monkeypatch.setattr(coord, "sha256_fingerprint", _explode)

    out = coord.step_02_fingerprint(
        paths, state_dir, precomputed_hashes=valid_hashes,
    )
    assert out == valid_hashes
    # Step 2 must still record sha256_pre.txt for downstream tooling.
    assert (state_dir / "sha256_pre.txt").exists()


# ---------------------------------------------------------------------------
# Test 3: invalid / sentinel precomputed hashes -> honest fallback.
# ---------------------------------------------------------------------------


def test_step_02_fingerprint_falls_back_on_invalid_precomputed(
    monkeypatch, tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    ev = tmp_path / "evidence.bin"
    ev.write_bytes(b"\x01" * 32)
    paths = [str(ev)]

    sentinel_hashes = {str(ev): "FILE_NOT_FOUND"}

    fallback_called = {"n": 0}
    real_sf = coord.sha256_fingerprint

    def _spy(*args, **kwargs):
        fallback_called["n"] += 1
        return real_sf(*args, **kwargs)

    monkeypatch.setattr(coord, "sha256_fingerprint", _spy)

    out = coord.step_02_fingerprint(
        paths, state_dir, precomputed_hashes=sentinel_hashes,
    )
    assert fallback_called["n"] == 1, (
        "Sentinel precomputed hashes must trigger honest fallback recompute"
    )
    assert out[str(ev)] != "FILE_NOT_FOUND"
    assert len(out[str(ev)]) == 64  # real sha256 hex

    # Different evidence-path set must also trigger fallback.
    fallback_called["n"] = 0
    ev2 = tmp_path / "second.bin"
    ev2.write_bytes(b"\x02" * 8)
    mismatched = {str(ev): "a" * 64}  # missing ev2 -> set mismatch
    out2 = coord.step_02_fingerprint(
        [str(ev), str(ev2)], state_dir,
        precomputed_hashes=mismatched,
    )
    assert fallback_called["n"] == 1, (
        "Mismatched evidence-path set must trigger honest recompute"
    )
    assert set(out2.keys()) == {str(ev), str(ev2)}


# ---------------------------------------------------------------------------
# Test 4: no NEW cross-run on-disk SHA cache introduced.
# ---------------------------------------------------------------------------


_CACHE_FORBIDDEN_SUBSTRINGS = (
    "sha256 cache",
    "cache sha256",
    "loading sha256_pre.json to skip",
    "load sha256_pre.json to skip",
    "read .evidence_hash to skip",
)

_CACHE_READ_VERBS = ("read_state", "load_state", "json.load", "open(")


def _changed_files_against_head() -> list[Path]:
    res = subprocess.run(
        ["git", "diff", "HEAD", "--name-only"],
        capture_output=True, text=True, cwd=str(_REPO_ROOT), timeout=30,
    )
    out = res.stdout or ""
    return [
        _REPO_ROOT / ln.strip()
        for ln in out.splitlines() if ln.strip()
    ]


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
        # Skip this test file itself (lists the forbidden tokens).
        if path.resolve() == Path(__file__).resolve():
            continue
        for ln in _added_lines_for(path):
            low = ln.lower()
            for sub in _CACHE_FORBIDDEN_SUBSTRINGS:
                if sub in low:
                    offenders.append((str(path), sub, ln.strip()))
            if (
                "sha256" in low
                and any(v in low for v in _CACHE_READ_VERBS)
                and "skip" in low
            ):
                offenders.append(
                    (str(path), "sha256+read+skip", ln.strip()),
                )
            if ".evidence_hash" in low and "skip" in low:
                offenders.append(
                    (str(path), "evidence_hash+skip", ln.strip()),
                )
    assert not offenders, (
        "No cross-run sha256 cache may be introduced by this rung:\n"
        + "\n".join(f"  {p} :: [{kind}] {ln}" for p, kind, ln in offenders)
    )


# ---------------------------------------------------------------------------
# Test 5: SHA read/buffer/hash-loop logic unchanged in this rung.
# ---------------------------------------------------------------------------


_SHA_FORBIDDEN_TOKENS = (
    "hashlib.sha256",
    ".read(",
    "readinto",
    "block_size",
    "buffer",
    "fadvise",
    "update(",
)


def test_sha256_hashloop_logic_unchanged_by_this_rung() -> None:
    """Inspect added lines in coordinator.py; none may touch hot path."""
    res = subprocess.run(
        ["git", "diff", "HEAD", "--", str(_COORDINATOR)],
        capture_output=True, text=True, cwd=str(_REPO_ROOT), timeout=30,
    )
    diff = res.stdout or ""
    offenders: list[tuple[str, str]] = []
    for raw in diff.splitlines():
        if not raw.startswith("+") or raw.startswith("+++"):
            continue
        body = raw[1:]
        for tok in _SHA_FORBIDDEN_TOKENS:
            if tok in body:
                offenders.append((tok, body.strip()))
    assert not offenders, (
        "This rung must NOT modify SHA read/buffer/hash-loop logic:\n"
        + "\n".join(f"  [{t}] {ln}" for t, ln in offenders)
    )


# ---------------------------------------------------------------------------
# Test 6: stop-after-step 3 still exits 0, emits STEP123_TIMING, API-free.
# ---------------------------------------------------------------------------


def _build_synthetic_evidence(tmp_path: Path) -> tuple[Path, Path, Path]:
    mem = tmp_path / "memory.img"
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


def test_stop_after_step_3_remains_api_free_and_emits_timing(
    tmp_path: Path,
) -> None:
    mem, disk, mount = _build_synthetic_evidence(tmp_path)
    env = os.environ.copy()
    env["SIFT_ASSERT_NO_LIVE_CALL"] = "1"
    env["PYTHONPATH"] = (
        f"{_REPO_ROOT / 'src'}{os.pathsep}{_REPO_ROOT}"
    )
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
    assert "STEP123_TIMING" in combined
    assert "sha_pre_s=" in combined
    assert "sha_pre_invalidation_s=" in combined
    assert "total_step1_3_s=" in combined

    for forbidden in ("STEP 4", "AI TOOL SELECTION", "LIVE: Calling", "STEP 6"):
        assert forbidden not in combined, (
            f"stop-after-step 3 leaked into '{forbidden}':\n{combined}"
        )


# ---------------------------------------------------------------------------
# Test 7: no dataset literals introduced (IPv4 addresses).
# ---------------------------------------------------------------------------


_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
_ALLOWED_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}


def test_no_dataset_literals_in_changed_files() -> None:
    offenders: list[tuple[str, str]] = []
    for path in _changed_files_against_head():
        if not path.exists() or not path.is_file():
            continue
        if path.suffix not in {".py", ".sh", ".md", ".json"}:
            continue
        if path.resolve() == Path(__file__).resolve():
            continue
        for ln in _added_lines_for(path):
            for ip in _IPV4_RE.findall(ln):
                if ip in _ALLOWED_IPS:
                    continue
                offenders.append((str(path), f"{ip} :: {ln.strip()}"))
    assert not offenders, (
        "Dataset literals (IPv4 addresses) must not appear in changed "
        "source for this rung:\n"
        + "\n".join(f"  {p} :: {ln}" for p, ln in offenders)
    )
