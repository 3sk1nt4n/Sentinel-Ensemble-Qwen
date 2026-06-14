"""Shared fixtures for pipeline tests.

Mocks run_volatility so pipeline tests don't need a real evidence image.
"""

import pytest

from tests.test_tools.conftest import FIXTURE_DATA, _fake_run_volatility


@pytest.fixture(autouse=True)
def _mock_run_volatility_pipeline(monkeypatch):
    """Mock run_volatility in ALL modules that import it."""
    monkeypatch.setattr(
        "sift_sentinel.tools.common.run_volatility", _fake_run_volatility,
    )
    monkeypatch.setattr(
        "sift_sentinel.tools.memory.run_volatility", _fake_run_volatility,
    )
    monkeypatch.setattr(
        "sift_sentinel.tools.memory_extended.run_volatility", _fake_run_volatility,
    )
    monkeypatch.setattr(
        "sift_sentinel.tools.memory_extended2.run_volatility", _fake_run_volatility,
    )
    monkeypatch.setattr(
        "sift_sentinel.coordinator.run_volatility", _fake_run_volatility,
    )


@pytest.fixture(autouse=True)
def _init_tool_health_for_all_tests():
    """Initialize per-run tool health tracker for every test in this
    directory. Session 6a.5 made new_tool_health() a required call at
    pipeline start; this fixture preserves backward compatibility for
    pre-6a.5 tests that exercise run_tool directly. Tests that need
    to assert uninitialized behavior (e.g.,
    test_get_tool_health_raises_when_uninitialized) use monkeypatch
    to reset _tool_health to None AFTER this fixture runs."""
    from sift_sentinel.coordinator import new_tool_health
    new_tool_health()
    yield
