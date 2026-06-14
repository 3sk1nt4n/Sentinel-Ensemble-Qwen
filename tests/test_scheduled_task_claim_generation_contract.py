from pathlib import Path
import re


def test_inv2_prompt_allows_scheduled_task_claim_types():
    text = Path("src/sift_sentinel/coordinator.py").read_text(errors="replace")
    assert "scheduled_task" in text
    assert "scheduled_task_action" in text
    assert "scheduled_task_fact" in text
    assert "task_name" in text
    assert "task_path" in text


def test_self_correction_claim_block_allows_scheduled_task_claim_types():
    text = Path("src/sift_sentinel/correction/strategies.py").read_text(errors="replace")
    m = re.search(r"VALID_CLAIM_TYPES_BLOCK\s*=\s*'''(?P<block>.*?)'''", text, re.S)
    assert m
    block = m.group("block")
    assert "scheduled_task" in block
    assert "scheduled_task_action" in block
    assert "task_name" in block
