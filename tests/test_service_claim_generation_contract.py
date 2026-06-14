from pathlib import Path
import re


SERVICE_TYPES = {"service", "service_state", "service_binary"}


def _strategies_block():
    text = Path("src/sift_sentinel/correction/strategies.py").read_text(errors="replace")
    m = re.search(r"VALID_CLAIM_TYPES_BLOCK\s*=\s*'''(?P<block>.*?)'''", text, re.S)
    assert m, "VALID_CLAIM_TYPES_BLOCK assignment not found"
    return m.group("block")


def test_inv2_prompt_allows_service_claim_types():
    text = Path("src/sift_sentinel/coordinator.py").read_text(errors="replace")
    for claim_type in SERVICE_TYPES:
        assert claim_type in text
    assert "vol_svcscan" in text
    assert "service_name" in text
    assert "binary_path" in text
    assert "state" in text


def test_self_correction_claim_block_allows_service_claim_types():
    block = _strategies_block()
    for claim_type in SERVICE_TYPES:
        assert claim_type in block
    assert "service_name" in block
    assert "binary_path" in block
    assert "state" in block
