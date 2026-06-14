from pathlib import Path
import re


DLL_TYPES = {
    "process_dll_loaded",
    "dll_loaded",
    "dll_path_loaded",
}


def _strategies_block():
    text = Path("src/sift_sentinel/correction/strategies.py").read_text(errors="replace")
    m = re.search(r"VALID_CLAIM_TYPES_BLOCK\s*=\s*'''(?P<block>.*?)'''", text, re.S)
    assert m, "VALID_CLAIM_TYPES_BLOCK assignment not found"
    return m.group("block")


def test_inv2_prompt_allows_dll_claim_types():
    text = Path("src/sift_sentinel/coordinator.py").read_text(errors="replace")
    for claim_type in DLL_TYPES:
        assert claim_type in text
    assert "dll_name" in text
    assert "dll_path" in text


def test_self_correction_block_allows_dll_claim_types():
    block = _strategies_block()
    for claim_type in DLL_TYPES:
        assert claim_type in block
    assert "dll_name" in block
    assert "dll_path" in block
