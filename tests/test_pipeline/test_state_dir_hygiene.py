"""Tests for state-dir hygiene (blind-run integrity).

Verifies hash_gated_state_invalidation clears state when evidence changes,
preserves when same, handles first-run migration, and writes marker correctly.
Tests exercise the production function directly.
"""
from __future__ import annotations
import hashlib
import json
import logging
from pathlib import Path

import pytest

from sift_sentinel.coordinator import hash_gated_state_invalidation


def _fingerprint_for(pre_hashes: dict[str, str]) -> str:
    return hashlib.sha256(
        json.dumps(pre_hashes, sort_keys=True).encode()
    ).hexdigest()


class TestHashGatedStateInvalidation:

    def test_empty_hashes_returns_none(self, tmp_path: Path):
        state_dir = tmp_path / "state"
        result = hash_gated_state_invalidation(state_dir, {})
        assert result is None
        assert state_dir.exists()
        assert (state_dir / "tool_outputs").exists()
        assert not (state_dir / ".evidence_hash").exists()

    def test_fresh_run_creates_state_and_marker(self, tmp_path: Path):
        state_dir = tmp_path / "state"
        pre_hashes = {"/fake/mem.raw": "a" * 64}
        result = hash_gated_state_invalidation(state_dir, pre_hashes)
        assert result == _fingerprint_for(pre_hashes)
        assert state_dir.exists()
        assert (state_dir / ".evidence_hash").read_text().strip() == result

    def test_cleared_on_unmarked_prior_artifacts(self, tmp_path: Path):
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        (state_dir / "tool_outputs").mkdir()
        (state_dir / "findings_validated.json").write_text('{"old": "data"}')
        (state_dir / "tool_outputs" / "vol_pstree.json").write_text('{"stale": 1}')

        pre_hashes = {"/fake/mem.raw": "a" * 64}
        result = hash_gated_state_invalidation(state_dir, pre_hashes)

        assert result == _fingerprint_for(pre_hashes)
        assert state_dir.exists()
        assert not (state_dir / "findings_validated.json").exists()
        assert not (state_dir / "tool_outputs" / "vol_pstree.json").exists()
        assert (state_dir / ".evidence_hash").read_text().strip() == result

    def test_cleared_on_evidence_change(self, tmp_path: Path):
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        (state_dir / "findings_validated.json").write_text('{"prior": "run"}')

        old_hashes = {"/fake/old.raw": "x" * 64}
        (state_dir / ".evidence_hash").write_text(_fingerprint_for(old_hashes))

        new_hashes = {"/fake/new.raw": "y" * 64}
        result = hash_gated_state_invalidation(state_dir, new_hashes)

        assert result == _fingerprint_for(new_hashes)
        assert not (state_dir / "findings_validated.json").exists()
        assert (state_dir / ".evidence_hash").read_text().strip() == result

    def test_preserved_on_same_evidence(self, tmp_path: Path):
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        (state_dir / "findings_validated.json").write_text('{"resume": "data"}')

        pre_hashes = {"/fake/mem.raw": "a" * 64}
        (state_dir / ".evidence_hash").write_text(_fingerprint_for(pre_hashes))

        result = hash_gated_state_invalidation(state_dir, pre_hashes)

        assert result == _fingerprint_for(pre_hashes)
        assert (state_dir / "findings_validated.json").exists()
        assert json.loads((state_dir / "findings_validated.json").read_text()) == \
            {"resume": "data"}

    def test_fresh_empty_state_dir_no_clear(self, tmp_path: Path):
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        (state_dir / "tool_outputs").mkdir()

        pre_hashes = {"/fake/mem.raw": "a" * 64}
        result = hash_gated_state_invalidation(state_dir, pre_hashes)
        assert result == _fingerprint_for(pre_hashes)

    def test_logger_warnings_on_clear(self, tmp_path: Path, caplog):
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        (state_dir / "findings.json").write_text('{}')

        pre_hashes = {"/fake/mem.raw": "a" * 64}
        test_logger = logging.getLogger("test_hygiene")
        with caplog.at_level(logging.WARNING, logger="test_hygiene"):
            hash_gated_state_invalidation(state_dir, pre_hashes, test_logger)
        assert any("unmarked prior artifacts" in r.message for r in caplog.records)

    def test_logger_info_on_resume(self, tmp_path: Path, caplog):
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        pre_hashes = {"/fake/mem.raw": "a" * 64}
        (state_dir / ".evidence_hash").write_text(_fingerprint_for(pre_hashes))
        (state_dir / "old.json").write_text('{}')

        test_logger = logging.getLogger("test_hygiene")
        with caplog.at_level(logging.INFO, logger="test_hygiene"):
            hash_gated_state_invalidation(state_dir, pre_hashes, test_logger)
        assert any("Resume mode" in r.message for r in caplog.records)
