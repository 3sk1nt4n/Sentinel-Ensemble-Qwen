from __future__ import annotations
from pathlib import Path
import re
import inspect
import pytest


@pytest.fixture(autouse=True)
def _ensure_tracker_initialized(request):
    """All tests need a fresh tracker except the explicit uninitialized test.
    Prevents ordering fragility under pytest-randomly or plugin chains."""
    if "test_get_tool_health_raises_when_uninitialized" in request.node.name:
        yield
        return
    from sift_sentinel.coordinator import new_tool_health
    new_tool_health()
    yield


class TestToolHealthClass:
    """Class-level semantics and defensive copy."""

    def test_class_exists(self):
        from sift_sentinel.coordinator import _ToolHealth
        assert _ToolHealth is not None

    def test_slots_whitelist(self):
        from sift_sentinel.coordinator import _ToolHealth
        assert set(_ToolHealth.__slots__) == {
            "attempted", "succeeded", "failed",
        }

    def test_fresh_instance_is_empty(self):
        from sift_sentinel.coordinator import _ToolHealth
        s = _ToolHealth().summary()
        assert s["attempted"] == 0
        assert s["succeeded"] == 0
        assert s["failed"] == 0

    def test_mark_success(self):
        from sift_sentinel.coordinator import _ToolHealth
        h = _ToolHealth()
        h.mark_attempt("tool_a")
        h.mark_success("tool_a")
        s = h.summary()
        assert s["attempted"] == 1
        assert s["succeeded"] == 1
        assert s["failed"] == 0

    def test_mark_failure_with_mode(self):
        from sift_sentinel.coordinator import _ToolHealth
        h = _ToolHealth()
        h.mark_attempt("tool_b")
        h.mark_failure("tool_b", "binary missing", "binary_missing")
        s = h.summary()
        assert s["failed"] == 1
        assert s["failures"]["tool_b"]["error"] == "binary missing"
        assert s["failures"]["tool_b"]["failure_mode"] == "binary_missing"

    def test_error_capped_at_200(self):
        from sift_sentinel.coordinator import _ToolHealth
        h = _ToolHealth()
        h.mark_failure("tool_c", "X" * 500, "runtime_error")
        assert len(h.failed["tool_c"]["error"]) <= 200

    def test_summary_is_defensive_copy(self):
        from sift_sentinel.coordinator import _ToolHealth
        h = _ToolHealth()
        h.mark_failure("t", "err", "mode")
        s = h.summary()
        s["failures"]["t"]["error"] = "MUTATED"
        assert h.failed["t"]["error"] == "err"

    def test_attempt_is_idempotent(self):
        from sift_sentinel.coordinator import _ToolHealth
        h = _ToolHealth()
        h.mark_attempt("vol_pstree")
        h.mark_attempt("vol_pstree")
        h.mark_attempt("vol_pstree")
        assert h.summary()["attempted"] == 1


class TestReassignmentPattern:
    """Structural per-run isolation via reassignment."""

    def test_new_tool_health_returns_fresh_instance(self):
        from sift_sentinel import coordinator
        h1 = coordinator.new_tool_health()
        h1.mark_attempt("vol_pstree")
        h2 = coordinator.new_tool_health()
        assert h1 is not h2
        assert "vol_pstree" not in h2.attempted

    def test_old_reference_becomes_stale(self):
        from sift_sentinel import coordinator
        h1 = coordinator.new_tool_health()
        h1.mark_attempt("tool_a")
        coordinator.new_tool_health()
        coordinator.get_tool_health().mark_attempt("tool_b")
        assert "tool_b" not in h1.attempted
        assert "tool_a" in h1.attempted

    def test_get_tool_health_raises_when_uninitialized(self, monkeypatch):
        from sift_sentinel import coordinator
        monkeypatch.setattr(coordinator, "_tool_health", None)
        with pytest.raises(RuntimeError, match="new_tool_health"):
            coordinator.get_tool_health()


class TestRunToolInstrumentation:
    """run_tool wrapper via _run_tool_inner."""

    def test_unknown_tool_marks_failure_with_mode(self):
        from sift_sentinel.coordinator import get_tool_health, run_tool
        result = run_tool("made_up_tool_xyz", "/fake/mem.raw", "/fake/disk.E01")
        assert "error" in result
        assert result.get("failure_mode") == "unknown_tool"
        h = get_tool_health()
        assert "made_up_tool_xyz" in h.attempted
        assert "made_up_tool_xyz" in h.failed
        assert h.failed["made_up_tool_xyz"]["failure_mode"] == "unknown_tool"

    def test_attempt_marked_before_lookup(self):
        from sift_sentinel.coordinator import get_tool_health, run_tool
        run_tool("made_up_tool_xyz", "/fake/mem.raw", "/fake/disk.E01")
        h = get_tool_health()
        assert "made_up_tool_xyz" in h.attempted
        assert "made_up_tool_xyz" in h.failed

    def test_run_tool_signature_has_expected_params(self):
        from sift_sentinel.coordinator import run_tool
        sig = inspect.signature(run_tool)
        params = list(sig.parameters)
        assert params[:3] == ["tool_name", "image_path", "disk_path"], (
            f"First 3 params must be positional str args, got {params[:3]}"
        )
        assert "mft_start" in sig.parameters
        assert "mft_end" in sig.parameters
        assert sig.parameters["mft_start"].default is not inspect.Parameter.empty
        assert sig.parameters["mft_end"].default is not inspect.Parameter.empty
        assert "health" not in sig.parameters, (
            "Reassignment pattern: health is module-level, not a param"
        )


class TestParallelPathContract:
    """run_tools_parallel invokes run_tool, which self-tracks health."""

    def test_parallel_path_tracks_health(self):
        from sift_sentinel.coordinator import get_tool_health, run_tool
        from sift_sentinel.tools.common import run_tools_parallel

        tasks = {
            "made_up_tool_xyz": (
                run_tool,
                ("made_up_tool_xyz", "/fake/mem.raw", "/fake/disk.E01"),
            ),
        }
        results = run_tools_parallel(tasks, max_workers=1)

        assert "error" in results["made_up_tool_xyz"]
        h = get_tool_health()
        assert "made_up_tool_xyz" in h.attempted
        assert "made_up_tool_xyz" in h.failed
        assert h.failed["made_up_tool_xyz"]["failure_mode"] == "unknown_tool"


class TestRule5Structural:
    """Rule 5: no persistent tool-result memory."""

    def test_no_persistent_cache_files_in_repo(self):
        forbidden_globs = [
            "smoke_test_results*.json",
            "tool_health_cache*",
            "tool_results_cache*",
            "*.tool_health.pkl",
        ]
        root = Path(".")
        for pat in forbidden_globs:
            matches = list(root.glob(pat))
            assert not matches, f"Rule 5: {pat} -> {matches}"

    def test_coordinator_does_not_reference_cache_files(self):
        src = Path("src/sift_sentinel/coordinator.py").read_text()
        patterns = [
            r"smoke_test_results",
            r"tool_health_cache",
            r"tool_results_cache",
            r"\.tool_health\.pkl",
        ]
        for pat in patterns:
            assert not re.search(pat, src), (
                f"Rule 5 risk: {pat!r} in coordinator.py"
            )

    def test_run_tool_creates_no_cache_files(self, tmp_path, monkeypatch):
        from sift_sentinel import coordinator
        from sift_sentinel.coordinator import run_tool

        monkeypatch.chdir(tmp_path)
        monkeypatch.setitem(
            coordinator._TOOL_REGISTRY,
            "__rule5_test_tool__",
            (lambda *a, **k: {
                "tool_name": "__rule5_test_tool__",
                "output": [],
                "record_count": 0,
            }, "memory"),
        )
        for _ in range(5):
            run_tool("__rule5_test_tool__", "/fake/mem.raw", "/fake/disk.E01")

        cache_globs = [
            "*smoke*", "*tool_health*", "*tool_cache*", "*.pickle",
        ]
        for pat in cache_globs:
            matches = list(tmp_path.rglob(pat))
            assert not matches, f"Rule 5 runtime: {matches}"


class TestPipelineWiring:
    """run_pipeline.py initializes and logs tracker."""

    def test_run_pipeline_calls_new_tool_health(self):
        src = Path("run_pipeline.py").read_text()
        assert "new_tool_health()" in src, (
            "run_pipeline.py must call new_tool_health() at pipeline start"
        )

    def test_run_pipeline_logs_tool_health_summary(self):
        src = Path("run_pipeline.py").read_text()
        assert "TOOL HEALTH" in src
        assert "get_tool_health()" in src
