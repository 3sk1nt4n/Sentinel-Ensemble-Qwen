from pathlib import Path
import re


ENVVAR_TYPES = {
    "process_envvar",
    "process_envvar_contains",
    "envvar",
}


def _strategies_block():
    text = Path("src/sift_sentinel/correction/strategies.py").read_text(errors="replace")
    m = re.search(r"VALID_CLAIM_TYPES_BLOCK\s*=\s*'''(?P<block>.*?)'''", text, re.S)
    assert m
    return m.group("block")


def test_inv2_prompt_allows_envvar_claim_types():
    text = Path("src/sift_sentinel/coordinator.py").read_text(errors="replace")
    for claim_type in ENVVAR_TYPES:
        assert claim_type in text
    assert "variable" in text
    assert "contains" in text


def test_self_correction_claim_block_allows_envvar_claim_types():
    block = _strategies_block()
    for claim_type in ENVVAR_TYPES:
        assert claim_type in block
    assert "variable" in block
    assert "contains" in block
