"""Global test fixtures -- ensure environment isolation between tests."""

import pytest


@pytest.fixture(autouse=True)
def _dry_run_mode(monkeypatch):
    """Set SIFT_DRY_RUN=1 and redirect DISK_MOUNT_PATH to avoid scanning
    real mounted disks during tests. Individual tests can override
    DISK_MOUNT_PATH via monkeypatch for specific mounts."""
    monkeypatch.setenv("SIFT_DRY_RUN", "1")
    monkeypatch.setattr(
        "sift_sentinel.tools.disk.DISK_MOUNT_PATH",
        "/nonexistent/test_mount",
    )
    monkeypatch.setattr(
        "sift_sentinel.tools.disk_extended.DISK_MOUNT_PATH",
        "/nonexistent/test_mount",
    )
    # The run-level Volatility result cache is module-level and would
    # otherwise persist across test methods; each test is a fresh "run", so
    # clear it for isolation (production keeps it for the whole pipeline run,
    # where same image+tool deterministically yields the same result).
    try:
        from sift_sentinel.tools.common import clear_tool_result_cache
        clear_tool_result_cache()
    except Exception:
        pass
