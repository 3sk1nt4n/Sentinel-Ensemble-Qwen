from pathlib import Path
import re

from sift_sentinel.tools import capabilities as cap


SSDT_TYPES = {"ssdt_integrity", "kernel_ssdt_entry"}


def _strategies_block():
    text = Path("src/sift_sentinel/correction/strategies.py").read_text(errors="replace")
    m = re.search(r"VALID_CLAIM_TYPES_BLOCK\s*=\s*'''(?P<block>.*?)'''", text, re.S)
    assert m, "VALID_CLAIM_TYPES_BLOCK assignment not found"
    return m.group("block")


def test_inv2_prompt_allows_ssdt_claim_types():
    text = Path("src/sift_sentinel/coordinator.py").read_text(errors="replace")
    for claim_type in SSDT_TYPES:
        assert claim_type in text
    assert "vol_ssdt" in text
    assert "index" in text
    assert "module" in text
    assert "symbol" in text


def test_self_correction_claim_block_allows_ssdt_claim_types():
    block = _strategies_block()
    for claim_type in SSDT_TYPES:
        assert claim_type in block
    assert "index" in block
    assert "module" in block
    assert "symbol" in block


def test_vol_ssdt_has_capability_declaration():
    assert cap.get_capability("vol_ssdt") is not None
