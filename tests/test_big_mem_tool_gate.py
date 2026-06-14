"""Big-memory tool gate: on a LARGE image, drop slow coverage-redundant tools.

vol_hollowprocesses ran 90s for 0 records on the 17.7 GB acme image and its
hollowing class is already covered by the malfind prefix + psxview/ldrmodules.
On a small image it is cheap, so it is kept. run_strings / vol_handles are NOT
dropped by default (real unique coverage); the operator opts them in.
"""
from sift_sentinel.coordinator import big_mem_prune, BIG_MEM_THRESHOLD_GB


_SEL = ["vol_malfind", "vol_hollowprocesses", "run_strings", "vol_handles",
        "vol_pstree", "parse_event_logs"]


def test_large_image_drops_hollowprocesses_by_default():
    pruned, dropped = big_mem_prune(_SEL, 17.7, env={})
    assert "vol_hollowprocesses" not in pruned
    assert dropped == ["vol_hollowprocesses"]
    # nothing else is touched -- malfind/strings/handles survive
    assert "vol_malfind" in pruned and "run_strings" in pruned and "vol_handles" in pruned


def test_small_image_keeps_everything():
    pruned, dropped = big_mem_prune(_SEL, 4.0, env={})
    assert dropped == []
    assert pruned == _SEL


def test_threshold_boundary_inclusive():
    # exactly at the threshold counts as "big".
    _, dropped = big_mem_prune(_SEL, BIG_MEM_THRESHOLD_GB, env={})
    assert dropped == ["vol_hollowprocesses"]


def test_kill_switch_disables_gate():
    pruned, dropped = big_mem_prune(_SEL, 17.7, env={"SIFT_BIG_MEM_TOOL_GATE": "0"})
    assert dropped == [] and pruned == _SEL


def test_operator_can_add_extra_drops():
    pruned, dropped = big_mem_prune(
        _SEL, 17.7, env={"SIFT_BIG_MEM_DROP": "run_strings, vol_handles"})
    assert set(dropped) == {"vol_hollowprocesses", "run_strings", "vol_handles"}
    assert "vol_malfind" in pruned and "vol_pstree" in pruned   # essentials kept


def test_custom_threshold_env():
    # raise the bar to 20 GB -> a 17.7 GB image is no longer "big".
    _, dropped = big_mem_prune(_SEL, 17.7, env={"SIFT_BIG_MEM_GB": "20"})
    assert dropped == []


def test_no_image_size_keeps_everything():
    pruned, dropped = big_mem_prune(_SEL, 0, env={})
    assert dropped == [] and pruned == _SEL
