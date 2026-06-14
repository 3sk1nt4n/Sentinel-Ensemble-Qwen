from pathlib import Path
import re


SID_TYPES = {
    "process_sid",
    "process_account_sid",
}


def _strategies_block():
    text = Path("src/sift_sentinel/correction/strategies.py").read_text(errors="replace")
    m = re.search(r"VALID_CLAIM_TYPES_BLOCK\s*=\s*'''(?P<block>.*?)'''", text, re.S)
    assert m, "VALID_CLAIM_TYPES_BLOCK assignment not found"
    return m.group("block")


def test_inv2_prompt_allows_sid_claim_types():
    text = Path("src/sift_sentinel/coordinator.py").read_text(errors="replace")
    for claim_type in SID_TYPES:
        assert claim_type in text
    assert "sid" in text.lower()
    assert "account" in text.lower()


def test_self_correction_block_allows_sid_claim_types():
    block = _strategies_block()
    for claim_type in SID_TYPES:
        assert claim_type in block
    assert "sid" in block.lower()
    assert "account" in block.lower()
