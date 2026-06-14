from pathlib import Path

from sift_sentinel.runtime.tool_value_selection import (
    SEMANTIC_HIGH_VALUE_TOOLS,
    is_semantic_high_value,
    rebalance_selected_tools,
    semantic_bucket,
    tool_profile,
)


def test_high_value_is_semantic_not_dataset_count_based(tmp_path):
    for tool in ("parse_prefetch", "run_srumecmd", "sleuthkit_mactime"):
        assert tool in SEMANTIC_HIGH_VALUE_TOOLS
        assert is_semantic_high_value(tool)

    # Missing artifacts change artifact_status, not semantic value.
    for tool in ("parse_prefetch", "run_srumecmd", "sleuthkit_mactime"):
        profile = tool_profile(tool, disk_mount=str(tmp_path), env={})
        assert profile["semantic_high_value"] is True
        assert profile["semantic_bucket"] in {
            "disk_execution", "resource_usage",
        }


def test_semantic_buckets_are_stable():
    assert semantic_bucket("parse_prefetch") == "disk_execution"
    assert semantic_bucket("run_mftecmd") == "disk_execution"
    assert semantic_bucket("sleuthkit_mactime") == "disk_execution"
    assert semantic_bucket("run_srumecmd") == "resource_usage"
    assert semantic_bucket("parse_event_logs") == "logs_script_wmi"


def test_mactime_deferred_without_bodyfile_and_mftecmd_injected(tmp_path):
    selected = ["vol_pstree", "sleuthkit_mactime"]
    out, actions = rebalance_selected_tools(
        selected,
        inv1_supported={"vol_pstree", "sleuthkit_mactime", "run_mftecmd"},
        disk_mount=str(tmp_path),
        max_selected=30,
        env={},
    )

    assert "sleuthkit_mactime" not in out
    assert "run_mftecmd" in out
    joined = " ".join(actions)
    assert "deferred sleuthkit_mactime" in joined
    assert "semantic_high_value=true" in joined
    assert "injected run_mftecmd" in joined


def test_mactime_kept_when_bodyfile_exists(tmp_path):
    bodyfile = tmp_path / "bodyfile.txt"
    bodyfile.write_text("0|x|0|0|0|0|0|0|0|0|0\n")

    selected = ["vol_pstree", "sleuthkit_mactime"]
    out, actions = rebalance_selected_tools(
        selected,
        inv1_supported={"vol_pstree", "sleuthkit_mactime", "run_mftecmd"},
        disk_mount=str(tmp_path),
        max_selected=30,
        env={"SIFT_SLEUTHKIT_BODYFILE": str(bodyfile)},
    )

    assert "sleuthkit_mactime" in out
    assert "run_mftecmd" not in out
    assert any("kept sleuthkit_mactime" in a for a in actions)


def test_mftecmd_not_injected_when_not_supported(tmp_path):
    selected = ["vol_pstree", "sleuthkit_mactime"]
    out, actions = rebalance_selected_tools(
        selected,
        inv1_supported={"vol_pstree", "sleuthkit_mactime"},
        disk_mount=str(tmp_path),
        max_selected=30,
        env={},
    )

    assert "sleuthkit_mactime" not in out
    assert "run_mftecmd" not in out


def test_run_pipeline_has_rebalance_hook():
    text = Path("run_pipeline.py").read_text()
    assert "rebalance_selected_tools" in text
    assert "A+ tool rebalance" in text
