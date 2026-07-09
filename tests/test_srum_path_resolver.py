"""TDD: SRUM SRUDB.dat path-robustness (universal case-insensitive resolver).

The coordinator passes a CANONICAL case path to run_srumecmd. On NTFS
mounts that preserve the original (often lowercase) filesystem case,
the canonical path may not exist. _resolve_srudb_path must find the
file by case-insensitive os.walk under the estimated mount root.

Dataset-agnostic: synthetic /tmp mounts only; no real evidence paths.
"""
import os
from pathlib import Path

import pytest


def _import_resolver():
    from sift_sentinel.tools import generic as g
    return g._resolve_srudb_path


def _import_run_srumecmd():
    from sift_sentinel.tools.generic import run_srumecmd
    return run_srumecmd


# ── path-resolver unit tests ──────────────────────────────────────────────────

def test_resolver_returns_hint_when_it_exists(tmp_path):
    sru = tmp_path / "Windows" / "System32" / "sru"
    sru.mkdir(parents=True)
    srudb = sru / "SRUDB.dat"
    srudb.write_bytes(b"ESE")
    resolve = _import_resolver()
    assert resolve(str(srudb)) == str(srudb)


def test_resolver_finds_lowercase_srudb_from_uppercase_hint(tmp_path):
    """Standard NTFS case-mismatch: file stored lowercase, hint is canonical."""
    sru = tmp_path / "windows" / "system32" / "sru"
    sru.mkdir(parents=True)
    srudb = sru / "SRUDB.dat"
    srudb.write_bytes(b"ESE")
    canonical_hint = str(tmp_path / "Windows" / "System32" / "sru" / "SRUDB.dat")
    resolve = _import_resolver()
    result = resolve(canonical_hint)
    assert result is not None
    assert os.path.exists(result)
    assert result.lower().endswith("srudb.dat")


def test_resolver_finds_drive_letter_layout(tmp_path):
    """Drive-letter layout: mount_root/C/Windows/System32/sru/SRUDB.dat."""
    sru = tmp_path / "C" / "Windows" / "System32" / "sru"
    sru.mkdir(parents=True)
    srudb = sru / "SRUDB.dat"
    srudb.write_bytes(b"ESE")
    canonical_hint = str(tmp_path / "Windows" / "System32" / "sru" / "SRUDB.dat")
    resolve = _import_resolver()
    result = resolve(canonical_hint)
    assert result is not None
    assert os.path.exists(result)


def test_resolver_returns_none_when_not_found(tmp_path):
    hint = str(tmp_path / "Windows" / "System32" / "sru" / "SRUDB.dat")
    resolve = _import_resolver()
    assert resolve(hint) is None


def test_resolver_returns_none_on_empty_string():
    resolve = _import_resolver()
    assert resolve("") is None


def test_resolver_does_not_match_non_sru_srudb(tmp_path):
    """A file named SRUDB.dat outside the sru/system32 chain must not match."""
    other = tmp_path / "some" / "other" / "dir"
    other.mkdir(parents=True)
    (other / "SRUDB.dat").write_bytes(b"fake")
    hint = str(tmp_path / "Windows" / "System32" / "sru" / "SRUDB.dat")
    resolve = _import_resolver()
    assert resolve(hint) is None


# ── run_srumecmd integration: path-resolution is applied ─────────────────────

def test_run_srumecmd_resolves_lowercase_mount(tmp_path):
    """run_srumecmd must succeed (or return a parse result, not artifact_missing)
    when SRUDB.dat exists at a lowercase path but the hint is canonical case."""
    sru = tmp_path / "windows" / "system32" / "sru"
    sru.mkdir(parents=True)
    # Write a valid (though tiny) ESE DB stub - pyesedb will fail to open it
    # but the resolver should kick in and not return artifact_missing.
    srudb = sru / "SRUDB.dat"
    srudb.write_bytes(b"\x00" * 16)
    canonical_hint = str(tmp_path / "Windows" / "System32" / "sru" / "SRUDB.dat")
    run_srumecmd = _import_run_srumecmd()
    result = run_srumecmd(canonical_hint)
    # failure_mode must NOT be artifact_missing (file was found via resolver)
    assert result.get("failure_mode") != "artifact_missing", (
        f"run_srumecmd returned artifact_missing even though SRUDB.dat "
        f"exists at a case-variant path: {result}"
    )
