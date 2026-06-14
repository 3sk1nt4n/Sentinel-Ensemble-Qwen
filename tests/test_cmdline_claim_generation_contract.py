from pathlib import Path
import re


CMDLINE_TYPES = {
    "process_cmdline",
    "process_cmdline_contains",
    "process_cmdline_empty",
}


def _valid_claim_types_block() -> str:
    text = Path("src/sift_sentinel/correction/strategies.py").read_text(errors="replace")
    m = re.search(r"VALID_CLAIM_TYPES_BLOCK\s*=\s*'''(?P<block>.*?)'''", text, re.S)
    assert m, "VALID_CLAIM_TYPES_BLOCK assignment not found"
    return m.group("block")


def test_coordinator_prompt_allows_process_cmdline_claim_types():
    text = Path("src/sift_sentinel/coordinator.py").read_text(errors="replace")

    for claim_type in CMDLINE_TYPES:
        assert claim_type in text

    assert '"source_tools": ["vol_cmdline"]' in text or '\\"source_tools\\": [\\"vol_cmdline\\"]' in text
    assert "Args field" in text
    assert "do not use it when Args is missing" in text


def test_self_correction_claim_block_allows_process_cmdline_claim_types():
    block = _valid_claim_types_block()

    for claim_type in CMDLINE_TYPES:
        assert claim_type in block

    assert "vol_cmdline" in block
    assert "Args is absent" in block or "Args field is absent" in block


def test_typed_validator_and_validator_ref_map_stay_aligned_for_cmdline_claims():
    from sift_sentinel.validation import typed_validator as tv
    from sift_sentinel.validation import validator

    for claim_type in CMDLINE_TYPES:
        assert claim_type in tv._TYPED_CHECKERS
        assert claim_type in tv.TYPED_SUPPORTED_CLAIM_TYPES
        assert validator._CLAIM_TYPE_TO_FACT_TYPE[claim_type] == "process_cmdline_fact"
