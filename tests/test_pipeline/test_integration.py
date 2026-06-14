"""Integration test: full 16-step pipeline in dry_run mode with cached data."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sift_sentinel.coordinator import BOOTSTRAP_TOOLS, MANDATORY_TOOLS, run_pipeline


class TestFullPipelineIntegration:
    """Run the real pipeline end-to-end with dry_run=True and cached_outputs/."""

    @pytest.fixture(autouse=True)
    def pipeline_result(self, tmp_path):
        """Run the pipeline once; share the result across all tests."""
        self.state_dir = tmp_path
        self.summary = run_pipeline(dry_run=True, state_dir=str(tmp_path))

    # ── 1. Completes without exception ──────────────────────────────────

    def test_completes_without_exception(self):
        assert self.summary is not None

    # ── 2. Returns status="completed" ───────────────────────────────────

    def test_status_completed(self):
        assert self.summary["status"] == "completed"

    # ── 3. State directory files ────────────────────────────────────────

    def test_sha256_pre_exists(self):
        assert (self.state_dir / "sha256_pre.txt").exists()

    def test_sha256_post_exists(self):
        assert (self.state_dir / "sha256_post.txt").exists()

    def test_tool_outputs_dir_exists(self):
        assert (self.state_dir / "tool_outputs").is_dir()

    def test_bootstrap_tool_jsons_exist(self):
        tool_dir = self.state_dir / "tool_outputs"
        for name in BOOTSTRAP_TOOLS:
            assert (tool_dir / f"{name}.json").exists(), f"missing {name}.json"

    def test_reference_set_exists_and_nonempty(self):
        path = self.state_dir / "reference_set.json"
        assert path.exists()
        data = json.loads(path.read_text())
        assert len(data) > 0

    def test_inv1_response_exists(self):
        assert (self.state_dir / "inv1_response.json").exists()

    def test_inv2_response_exists(self):
        assert (self.state_dir / "inv2_response.json").exists()

    def test_findings_validated_exists(self):
        assert (self.state_dir / "findings_validated.json").exists()

    def test_pipeline_summary_exists(self):
        assert (self.state_dir / "pipeline_summary.json").exists()

    # ── 4. Reference set has entries ────────────────────────────────────

    def test_reference_set_has_entries(self):
        ref = json.loads(
            (self.state_dir / "reference_set.json").read_text(),
        )
        has_pids = len(ref.get("pid_to_process", {})) > 0
        has_hashes = len(ref.get("hashes", {})) > 0
        has_ts = len(ref.get("timestamps_per_artifact", {})) > 0
        assert has_pids or has_hashes or has_ts, (
            "reference set must have at least one entry in "
            "pids, hashes, or timestamps"
        )

    # ── 5. Integrity check (dry-run has no real evidence → sentinels fail) ─

    def test_integrity_match(self):
        """Dry-run evidence paths don't exist, so FILE_NOT_FOUND sentinels
        correctly fail the integrity check."""
        assert self.summary["integrity"]["match"] is False

    # ── 6. Elapsed time > 0 ─────────────────────────────────────────────

    def test_elapsed_positive(self):
        assert self.summary["elapsed_s"] > 0

    # ── 7. tools_run contains all 5 mandatory tools ─────────────────────

    def test_tools_run_contains_bootstrap(self):
        tools_run = set(self.summary["tools_run"])
        for name in BOOTSTRAP_TOOLS:
            assert name in tools_run, f"{name} not in tools_run"

    # ── 8. dry_run=True in summary ──────────────────────────────────────

    def test_dry_run_flag(self):
        assert self.summary["dry_run"] is True
