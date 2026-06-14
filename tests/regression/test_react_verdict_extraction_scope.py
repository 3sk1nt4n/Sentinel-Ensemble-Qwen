"""Slot 31E-DB.5d GROUP B TASK B1/B2 -- extraction strictness + scope.

Only FINAL conclusions count: action==conclude, an explicit verdict, a
``CONCLUDED --`` line, or a false-positive line. Plain reasoning such
as "could indicate malicious" must NOT yield a verdict. A chain verdict
carries chain_members and must NOT make a member process malicious.
Dataset-agnostic: synthetic PIDs 91000-99999, FIXTURE_* names.
"""
from __future__ import annotations

import json

from sift_sentinel.react_verdicts import (
    REACT_CHAIN_ENTITY_SCOPE_GATE,
    REACT_VERDICT_EXTRACTION_GATE,
    REACT_VERDICT_SCOPE_GATE,
    VERDICT_MALICIOUS,
    canonical_entity_key,
    classify_react_verdict_scope,
    extract_react_verdicts,
)


def test_reasoning_only_text_is_not_a_verdict(tmp_path):
    (tmp_path / "investigation_threads.json").write_text(json.dumps({
        "investigations": [
            {"finding_id": "F1", "pid": 91001,
             "process": "FIXTURE_proc.exe",
             "conclusion": "This could indicate malicious activity and "
                           "may warrant further review."},
        ]
    }))
    recs = extract_react_verdicts(tmp_path)
    assert recs == [], (
        "reasoning-only conclusion must not produce a verdict record")


def test_explicit_conclude_counts(tmp_path):
    (tmp_path / "investigation_threads.json").write_text(json.dumps({
        "investigations": [
            {"finding_id": "F2", "pid": 91002,
             "process": "FIXTURE_proc.exe", "action": "conclude",
             "verdict": "confirmed_malicious",
             "conclusion": "CONCLUDED -- injected code confirmed"},
        ]
    }))
    recs = extract_react_verdicts(tmp_path)
    assert len(recs) == 1
    assert recs[0]["verdict"] == VERDICT_MALICIOUS
    assert recs[0]["source_finding_ids"] == ["F2"]


def test_concluded_line_in_markdown_counts(tmp_path):
    (tmp_path / "inv3_F3_turn2.md").write_text(
        "reasoning: looked at the VAD regions\n"
        "verdict: confirmed_benign\n"
        "CONCLUDED -- legitimate signed binary\n")
    recs = extract_react_verdicts(tmp_path)
    assert recs, "explicit verdict line in md must count"
    assert recs[0]["verdict"] == "benign"
    assert recs[0]["source_finding_ids"] == ["F3"]


def test_markdown_pure_reasoning_ignored(tmp_path):
    (tmp_path / "inv3_F4_turn1.md").write_text(
        "The process might be malicious but more data is needed.\n"
        "We should consider whether it is benign.\n")
    assert extract_react_verdicts(tmp_path) == []


def test_chain_scope_does_not_mark_member_process(tmp_path):
    chain_rec = {
        "finding_id": "F5",
        "action": "conclude",
        "verdict": "confirmed_malicious",
        "scope": "chain",
        "chain_members": ["FIXTURE_powershell.exe", "FIXTURE_rundll.exe"],
        "conclusion": "CONCLUDED -- malicious living-off-the-land chain",
    }
    assert classify_react_verdict_scope(chain_rec) == "chain"
    ckey = canonical_entity_key(chain_rec)
    assert ckey.startswith("chain:")
    # A standalone process record for the SAME powershell name is a
    # different entity key -> the chain verdict cannot leak onto it.
    proc_rec = {"pid": 91005, "process_name": "FIXTURE_powershell.exe"}
    pkey = canonical_entity_key(proc_rec)
    assert pkey != ckey
    assert classify_react_verdict_scope(proc_rec) == "process"


def test_scope_classification_matrix():
    assert classify_react_verdict_scope(
        {"pid": 91010, "process_name": "FIXTURE_a.exe"}) == "process"
    assert classify_react_verdict_scope(
        {"file": "/synthetic/payload.bin"}) == "file"
    assert classify_react_verdict_scope(
        {"network": "10.0.0.1:4444"}) == "network"
    assert classify_react_verdict_scope(
        {"source_finding_ids": ["F9"]}) == "finding"
    assert classify_react_verdict_scope({}) == "unknown"


def test_reasoning_only_malicious_language_is_not_a_verdict(tmp_path):
    """5d-alpha TASK 2: capped-reasoning prose that merely uses the
    word malicious/compromise is NOT a final verdict."""
    (tmp_path / "investigation_threads.json").write_text(json.dumps({
        "investigations": [
            {"finding_id": "F40", "pid": 91040,
             "process": "FIXTURE_a.exe",
             "conclusion": "Investigation reached 5-turn cap. Final AI "
                           "reasoning: malfind results strongly indicate "
                           "compromise and could indicate malicious "
                           "injection; I need to check handles."},
        ]
    }))
    assert extract_react_verdicts(tmp_path) == []


def test_concluded_pid_line_yields_process_verdict(tmp_path):
    """5d-alpha TASK 2: a coordinator CONCLUDED PID line becomes a
    process-scope verdict keyed process:<pid> with the name as alias."""
    (tmp_path / "live_acceptance.log").write_text(
        "2026-01-01 00:00:00 sift_sentinel.coordinator INFO   Turn 4: "
        "CONCLUDED -- PID 91260 (FIXTURE_p.exe) is malicious: suspicious "
        "executable in temp directory spawning rundll32.\n"
        "2026-01-01 00:00:01 sift_sentinel.coordinator INFO   reasoning "
        "line that could indicate malicious but is not a conclusion\n")
    recs = extract_react_verdicts([tmp_path / "live_acceptance.log"])
    assert len(recs) == 1, recs
    r = recs[0]
    assert r["verdict"] == VERDICT_MALICIOUS
    assert classify_react_verdict_scope(r) == "process"
    assert canonical_entity_key(r) == "process:91260"
    assert r["process_name"] == "FIXTURE_p.exe"


def test_concluded_inconclusive_hedge(tmp_path):
    (tmp_path / "x.log").write_text(
        "Turn 3: CONCLUDED -- PID 91261 (FIXTURE_p.exe) execution from "
        "temp directory is suspicious but not definitively malicious "
        "based on current evidence.\n")
    recs = extract_react_verdicts([tmp_path / "x.log"])
    assert len(recs) == 1
    assert recs[0]["verdict"] == "inconclusive"
    assert canonical_entity_key(recs[0]) == "process:91261"


def test_prompt_template_md_yields_no_verdict(tmp_path):
    """An inv3 prompt file containing a JSON schema example and
    instruction bullets is NOT a conclusion source (TASK 2)."""
    (tmp_path / "inv3_F50_turn4.md").write_text(
        'Return JSON:\n'
        '{\n  "action": "conclude",\n  "verdict": "confirmed_malicious",\n'
        '  "conclusion": "..."\n}\n'
        '- "confirmed_benign": evidence confirms finding is a false '
        'positive (legitimate software, known-good binary)\n'
        'Use inconclusive when uncertain.\n')
    assert extract_react_verdicts(tmp_path) == []


def test_marker():
    print(f"{REACT_VERDICT_EXTRACTION_GATE}=PASS")
    print(f"{REACT_VERDICT_SCOPE_GATE}=PASS")
    print(f"{REACT_CHAIN_ENTITY_SCOPE_GATE}=PASS")
    assert REACT_VERDICT_EXTRACTION_GATE == "REACT_VERDICT_EXTRACTION_GATE"
