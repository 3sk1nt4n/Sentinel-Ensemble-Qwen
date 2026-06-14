from pathlib import Path
import re


HANDLE_TYPES = {
    "process_handle",
    "process_handle_type",
    "process_handle_contains",
}


def test_inv2_prompt_allows_process_handle_claim_types():
    text = Path("src/sift_sentinel/coordinator.py").read_text(errors="replace")
    for claim_type in HANDLE_TYPES:
        assert claim_type in text
    assert "handle_type" in text
    assert "handle_name" in text
    assert "contains" in text


def test_self_correction_claim_block_allows_process_handle_claim_types():
    text = Path("src/sift_sentinel/correction/strategies.py").read_text(errors="replace")
    m = re.search(r"VALID_CLAIM_TYPES_BLOCK\s*=\s*'''(?P<block>.*?)'''", text, re.S)
    assert m, "VALID_CLAIM_TYPES_BLOCK assignment not found"
    block = m.group("block")
    for claim_type in HANDLE_TYPES:
        assert claim_type in block
    assert "handle_type" in block
    assert "handle_name" in block
