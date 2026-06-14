from pathlib import Path
import re


def test_inv2_prompt_allows_filesystem_timeline_claim_types():
    text = Path("src/sift_sentinel/coordinator.py").read_text(errors="replace")
    assert "filesystem_timeline" in text
    assert "mft_timeline" in text
    assert "filesystem_timeline_fact" in text
    assert "timestamp" in text
    assert "event_type" in text


def test_self_correction_claim_block_allows_filesystem_timeline_claim_types():
    text = Path("src/sift_sentinel/correction/strategies.py").read_text(errors="replace")
    m = re.search(r"VALID_CLAIM_TYPES_BLOCK\s*=\s*'''(?P<block>.*?)'''", text, re.S)
    assert m
    block = m.group("block")
    assert "filesystem_timeline" in block
    assert "mft_timeline" in block
    assert "timestamp" in block
