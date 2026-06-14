from pathlib import Path
import re


def test_inv2_prompt_allows_rdp_artifact_claim_type():
    text = Path("src/sift_sentinel/coordinator.py").read_text(errors="replace")
    assert "rdp_artifact" in text
    assert "rdp_artifact_fact" in text
    assert "remote_host" in text or "host" in text
    assert "artifact_type" in text


def test_self_correction_claim_block_allows_rdp_artifact_claim_type():
    text = Path("src/sift_sentinel/correction/strategies.py").read_text(errors="replace")
    m = re.search(r"VALID_CLAIM_TYPES_BLOCK\s*=\s*'''(?P<block>.*?)'''", text, re.S)
    assert m
    block = m.group("block")
    assert "rdp_artifact" in block
    assert "artifact_type" in block
    assert "contains" in block
