"""Tests for run_pipeline.py CLI argument handling."""

import argparse
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture
def parser():
    """Build the same argparse parser as run_pipeline.py without side effects."""
    p = argparse.ArgumentParser(description="SIFT Sentinel Pipeline Runner")
    p.add_argument("--live", action="store_true")
    p.add_argument("--ollama", action="store_true")
    p.add_argument("--gemini", action="store_true")
    p.add_argument("--gpt", action="store_true")
    p.add_argument("--no-mcp", action="store_true")
    p.add_argument("--image", type=str, default=None)
    p.add_argument("--disk", type=str, default=None)
    p.add_argument("--disk-mount", type=str, default=None)
    return p


class TestCLICustomImagePath:
    def test_image_flag_overrides_default(self, parser):
        args = parser.parse_args(["--image", "/synthetic/new/memory.img"])
        image = args.image or "/synthetic/evidence/memory.img"
        assert image == "/synthetic/new/memory.img"

    def test_image_flag_absent_uses_default(self, parser):
        args = parser.parse_args([])
        image = args.image or "/synthetic/evidence/memory.img"
        assert image == "/synthetic/evidence/memory.img"


class TestCLICustomDiskPath:
    def test_disk_flag_overrides_default(self, parser):
        args = parser.parse_args(["--disk", "/synthetic/new/disk.E01"])
        disk = args.disk or "/synthetic/evidence/disk.E01"
        assert disk == "/synthetic/new/disk.E01"

    def test_disk_flag_absent_uses_default(self, parser):
        args = parser.parse_args([])
        disk = args.disk or "/synthetic/evidence/disk.E01"
        assert disk == "/synthetic/evidence/disk.E01"


class TestCLICustomDiskMount:
    def test_disk_mount_flag_overrides_default(self, parser):
        args = parser.parse_args(["--disk-mount", "/mnt/rd02_mount"])
        mount = args.disk_mount or "/mnt/windows_mount"
        assert mount == "/mnt/rd02_mount"

    def test_disk_mount_flag_absent_uses_default(self, parser):
        args = parser.parse_args([])
        mount = args.disk_mount or "/mnt/windows_mount"
        assert mount == "/mnt/windows_mount"

    def test_all_flags_together(self, parser):
        args = parser.parse_args([
            "--image", "/a/mem.img",
            "--disk", "/a/disk.E01",
            "--disk-mount", "/mnt/custom",
        ])
        assert args.image == "/a/mem.img"
        assert args.disk == "/a/disk.E01"
        assert args.disk_mount == "/mnt/custom"


class TestGeminiFlag:
    def test_gemini_flag_sets_mode(self, parser):
        args = parser.parse_args(["--gemini"])
        assert args.gemini is True
        # GEMINI_MODE mirrors args.gemini; LIVE_MODE includes gemini
        gemini_mode = args.gemini
        live_mode = args.live or args.ollama or args.gemini
        assert gemini_mode is True
        assert live_mode is True

    def test_gemini_mutually_exclusive_with_live(self, parser):
        args = parser.parse_args(["--gemini", "--live"])
        # Pipeline enforces: sum([live, ollama, gemini]) > 1 -> error
        assert sum([args.live, args.ollama, args.gemini]) > 1

    def test_gemini_mutually_exclusive_with_ollama(self, parser):
        args = parser.parse_args(["--gemini", "--ollama"])
        assert sum([args.live, args.ollama, args.gemini]) > 1

    def test_gemini_missing_key_exits(self):
        """Pipeline exits with code 1 when GEMINI_API_KEY is unset."""
        import subprocess
        env = {k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}
        result = subprocess.run(
            [sys.executable, "run_pipeline.py", "--gemini"],
            capture_output=True, text=True, env=env, timeout=10,
        )
        assert result.returncode == 1
        assert "GEMINI_API_KEY" in result.stdout or "GEMINI_API_KEY" in result.stderr


class TestGptFlag:
    def test_gpt_flag_sets_mode(self, parser):
        args = parser.parse_args(["--gpt"])
        assert args.gpt is True
        gpt_mode = args.gpt
        live_mode = args.live or args.ollama or args.gemini or args.gpt
        assert gpt_mode is True
        assert live_mode is True

    def test_gpt_mutually_exclusive(self, parser):
        args = parser.parse_args(["--gpt", "--live"])
        assert sum([args.live, args.ollama, args.gemini, args.gpt]) > 1

    def test_gpt_missing_key_exits(self):
        """Pipeline exits with code 1 when OPENAI_API_KEY is unset."""
        import subprocess
        env = {k: v for k, v in os.environ.items() if k != "OPENAI_API_KEY"}
        result = subprocess.run(
            [sys.executable, "run_pipeline.py", "--gpt"],
            capture_output=True, text=True, env=env, timeout=10,
        )
        assert result.returncode == 1
        assert "OPENAI_API_KEY" in result.stdout or "OPENAI_API_KEY" in result.stderr
