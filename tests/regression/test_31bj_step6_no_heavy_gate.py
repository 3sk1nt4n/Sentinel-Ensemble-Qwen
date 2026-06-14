"""31BJ: Step 6 must submit all raw tools immediately.

Dataset-agnostic scheduler contract:
- heavy-first affects order only;
- no blocking heavy gate may delay later tools;
- result replay remains selected-order deterministic;
- no cache, no case key, no dataset literal.
"""

from pathlib import Path


def _step6_window() -> str:
    text = Path("run_pipeline.py").read_text(errors="replace")
    start = text.find("def _slot31d_parallel_dispatch")
    end = text.find("raw_to_run = []", start)
    assert start >= 0
    assert end > start
    return text[start:end]


def test_step6_has_no_blocking_heavy_gate():
    window = _step6_window()

    forbidden = [
        "Step6 HEAVY_GATE",
        "_HEAVY_GATE",
        "_STAGE_GATE_S",
        "_wave1",
        "_wave2",
        "as_completed(list(_gate_futs.keys())",
    ]
    for token in forbidden:
        assert token not in window


def test_step6_all_submitted_before_replay_phase():
    window = _step6_window()

    all_submit = window.find("Step6 DISPATCH all-submitted")
    replay = window.find("Replay-order record phase")
    assert all_submit >= 0
    assert replay > all_submit

    assert "_slot31bc_order(raw_to_run" in window
    assert "for _bc_tool in _ordered_disp:" in window
    assert "_submit_one(_bc_tool)" in window


def test_step6_preserves_selected_order_replay():
    window = _step6_window()

    assert "for _sel_tool in raw_to_run:" in window
    assert "submit_records.append((_sel_short, _sel_dup))" in window
    assert "ordered_results = []" in window
    assert "for short, _is_dup in submit_records:" in window
    assert "ordered_results.append(resolved[short])" in window


def test_step6_uses_as_completed_drain_not_selected_future_blocking():
    window = _step6_window()

    assert ".as_completed(list(_future_map.keys())" in window
    assert "payload.result(timeout=None)" not in window
    assert ".result(timeout=None)" not in window


def test_no_dataset_literals_in_31bj_test():
    text = Path(__file__).read_text(errors="replace")
    banned = [
        "base-" + "rd01",
        "rd-" + "01",
        "td" + "ungan",
        "sp" + "sql",
        "OUT" + "LOOK",
        "Wmi" + "PrvSE",
        "p." + "exe",
        "172." + "16.",
    ]
    for token in banned:
        assert token not in text
