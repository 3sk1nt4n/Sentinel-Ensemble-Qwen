from pathlib import Path
import re


def test_inv2_prompt_allows_wmi_subscription_claim_type():
    text = Path("src/sift_sentinel/coordinator.py").read_text(errors="replace")
    assert "wmi_subscription" in text
    assert "wmi_subscription_fact" in text
    assert "consumer_name" in text
    assert "filter_name" in text
    assert "query" in text


def test_self_correction_claim_block_allows_wmi_subscription_claim_type():
    text = Path("src/sift_sentinel/correction/strategies.py").read_text(errors="replace")
    m = re.search(r"VALID_CLAIM_TYPES_BLOCK\s*=\s*'''(?P<block>.*?)'''", text, re.S)
    assert m
    block = m.group("block")
    assert "wmi_subscription" in block
    assert "consumer_name" in block
    assert "filter_name" in block
    assert "query" in block
