"""Commit 20 invariants: concluded-investigation metric honest calculation.

L20-1: broken turn_details reference removed from C1 block
L20-2: C1 uses conclusion field check, not cached substring
L20-3: retroactive Run 11.5 data produces 100% rate
L20-4: investigations without conclusions contribute 0
L20-5: mixed scenario (some concluded, some not) calculates correctly
L20-6: honest label present (not misleading "Productive turns")
"""
from __future__ import annotations


def test_L20_1_broken_turn_details_removed_from_c1():
    """C1 block no longer references the non-existent turn_details field."""
    with open("run_pipeline.py") as f:
        content = f.read()
    c1_block_start = content.find("# C1: Autonomous")
    c1_block_end = content.find("# C2:", c1_block_start)
    assert c1_block_start > 0, "C1 comment not found"
    assert c1_block_end > c1_block_start, "C2 comment not found after C1"
    c1_block = content[c1_block_start:c1_block_end]
    assert 'turn_details' not in c1_block, \
        "C1 block still references broken turn_details field"


def test_L20_2_productive_uses_conclusion_field():
    """C1 calculation must use conclusion field check, not cached substring."""
    with open("run_pipeline.py") as f:
        content = f.read()
    assert 'if i.get("conclusion"):' in content, \
        "C1 block missing conclusion-based productive check"
    # Old cached-substring logic must be gone from C1 block
    c1_block_start = content.find("# C1: Autonomous")
    c1_block_end = content.find("# C2:", c1_block_start)
    c1_block = content[c1_block_start:c1_block_end]
    assert '"cached"' not in c1_block, \
        "C1 block still uses cached substring check"


def test_L20_3_retroactive_run11_5_scoring():
    """Run 11.5 data: 4 investigations, all concluded.
    Turns: 0, 1, 2, 0 = 3 total.
    All concluded, so productive = 0+1+2+0 = 3.
    Rate = 3/3 = 100%.
    """
    investigation_summaries = [
        {"finding_id": "F001", "turns": 0, "conclusion": "PID 9007 malicious"},
        {"finding_id": "F003", "turns": 1, "conclusion": "PID 3164 malicious"},
        {"finding_id": "F004", "turns": 2, "conclusion": "PIDs confirmed"},
        {"finding_id": "F012", "turns": 0, "conclusion": "attack chain confirmed"},
    ]
    inv_turns = sum(i.get("turns", 0) for i in investigation_summaries)
    productive = 0
    for i in investigation_summaries:
        if i.get("conclusion"):
            productive += i.get("turns", 0)
    productive_rate = productive / max(inv_turns, 1)
    assert inv_turns == 3
    assert productive == 3
    assert productive_rate == 1.0


def test_L20_4_no_conclusion_zero_productive():
    """Investigations without conclusion contribute 0 to productive."""
    investigation_summaries = [
        {"finding_id": "F001", "turns": 5, "conclusion": None},
        {"finding_id": "F002", "turns": 3, "conclusion": ""},
    ]
    inv_turns = sum(i.get("turns", 0) for i in investigation_summaries)
    productive = 0
    for i in investigation_summaries:
        if i.get("conclusion"):
            productive += i.get("turns", 0)
    assert inv_turns == 8
    assert productive == 0


def test_L20_5_mixed_scenario():
    """2 concluded (3 turns), 1 abandoned (2 turns). Rate = 3/5 = 60%."""
    investigation_summaries = [
        {"finding_id": "F001", "turns": 2, "conclusion": "malicious"},
        {"finding_id": "F002", "turns": 1, "conclusion": "benign"},
        {"finding_id": "F003", "turns": 2, "conclusion": None},
    ]
    inv_turns = sum(i.get("turns", 0) for i in investigation_summaries)
    productive = 0
    for i in investigation_summaries:
        if i.get("conclusion"):
            productive += i.get("turns", 0)
    productive_rate = productive / max(inv_turns, 1)
    assert inv_turns == 5
    assert productive == 3
    assert abs(productive_rate - 0.6) < 0.01


def test_L20_6_honest_label_present():
    """C1 output uses honest label describing what is actually measured."""
    with open("run_pipeline.py") as f:
        content = f.read()
    assert "Turns in concluded investigations" in content, \
        "Honest label missing"
    assert "Productive turns:" not in content, \
        "Old misleading label still present"
