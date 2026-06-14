"""31BK-A: Step6 structured parallelism regression.

Dataset-agnostic:
- Checks scheduler mechanics only.
- No evidence literals, no expected findings, no case key.
"""

from pathlib import Path


def test_step6_has_no_blocking_heavy_gate_and_has_lane_caps():
    src = Path("run_pipeline.py").read_text(errors="replace")

    assert "Step6 HEAVY_GATE" not in src
    assert "as_completed(list(_gate_futs.keys())" not in src
    assert "Step6 DISPATCH all-submitted" in src
    assert "SIFT_STEP6_VOL_TOTAL_CONCURRENCY" in src
    assert "SIFT_STEP6_VOL_HEAVY_CONCURRENCY" in src
    assert "SIFT_STEP6_DISK_CONCURRENCY" in src
    assert "Step6 LANE_START" in src


def test_step6_keeps_as_completed_drain_and_selected_order_replay():
    src = Path("run_pipeline.py").read_text(errors="replace")

    assert "as_completed(list(_future_map.keys())" in src
    assert "ordered_results = []" in src
    assert "for short, _is_dup in submit_records:" in src
    assert "ordered_results.append(resolved[short])" in src


def test_derived_ioc_has_local_fast_path_with_fallback():
    src = Path("run_pipeline.py").read_text(errors="replace")

    assert "Step6 DERIVED_LOCAL: extract_network_iocs" in src
    assert "fallback to MCP for extract_network_iocs" in src
    assert "_slot31c4_dispatch_one(" in src


def test_step6_write_tail_parallel_current_run_only():
    src = Path("run_pipeline.py").read_text(errors="replace")

    assert "SIFT_STEP6_WRITE_WORKERS" in src
    assert "Step6 write tail: wrote" in src
    assert "This is not a cache" in src


def test_explicit_timeout_is_not_c29_retried():
    src = Path("src/sift_sentinel/mcp_client.py").read_text(errors="replace")

    assert "_sift_mcp_explicit_timeout_text" in src
    assert "explicit tool timeout is not retried inside Step 6" in src
    assert "'failure_mode': 'timeout'" in src


def test_lecmd_is_bounded_not_full_users_tree_blind_scan():
    src = Path("src/sift_sentinel/tools/generic.py").read_text(errors="replace")

    assert "_sift_select_lnk_inputs" in src
    assert "SIFT_LECMD_MAX_LNK" in src
    assert "SIFT_LECMD_TIMEOUT_S" in src
    assert "selected_input_count" in src
    assert "no .lnk artifacts found" in src


def test_no_dataset_literals_in_this_regression():
    text = Path(__file__).read_text(errors="replace")
    banned = [
        "172." + "16.",
        "administrator." + "shieldbase",
        "td" + "ungan",
        "sp" + "sql",
        "base-" + "rd01",
        "rd-" + "01",
        "Wmi" + "PrvSE",
        "OUT" + "LOOK",
        "p." + "exe",
        "squirrel" + "directory",
    ]
    for token in banned:
        assert token not in text
