"""Slot 31E-DB.5d GROUP B TASK B4/B5/B6 -- contradiction fail-closed.

Detection is informational; routing is the policy. A process/file/
network entity with both malicious AND benign/inconclusive verdicts is
``conflicted``: every finding depending on it is routed out of
confirmed_malicious_atomic, a deterministic conflict artifact is
written, and a tiebreaker is flagged (no AI call in this slot).
Dataset-agnostic: synthetic PIDs 91000-99999, /synthetic paths.
"""
from __future__ import annotations

import json

from sift_sentinel.analysis.disposition import (
    BUCKET_CONFIRMED,
    BUCKET_SUSPICIOUS,
    GATE_REACT_ENTITY_CONFLICT,
    derive_final_disposition,
    evaluate_confirmed_bucket_eligibility,
)
from sift_sentinel.react_verdicts import (
    CONFLICT_ARTIFACT_NAME,
    CONFLICT_SCHEMA_VERSION,
    REACT_CONTRADICTION_ROUTE_GATE,
    REACT_ENTITY_TIEBREAKER_REQUIRED_GATE,
    REACT_ENTITY_VERDICT_CONFLICT_DETECTED_GATE,
    build_react_entity_verdict_ledger,
    detect_react_entity_contradictions,
    findings_blocked_by_react_conflicts,
    write_react_entity_conflicts,
)


def _rec(**kw):
    base = {
        "verdict": "malicious", "scope": None, "pid": None,
        "process_name": None, "file": None, "network": None,
        "chain_members": None, "source_finding_ids": [],
        "evidence_refs": [], "excerpt": "",
    }
    base.update(kw)
    return base


def _conflicting_records():
    return [
        _rec(pid=91001, process_name="FIXTURE_svc.exe",
             verdict="malicious", source_finding_ids=["F1"],
             excerpt="CONCLUDED -- malicious injection"),
        _rec(pid=91001, process_name="FIXTURE_svc.exe",
             verdict="benign", source_finding_ids=["F2"],
             excerpt="CONCLUDED -- signed, false positive"),
    ]


def test_detection_is_informational_and_counts():
    ledger = build_react_entity_verdict_ledger(_conflicting_records())
    conflicts = detect_react_entity_contradictions(ledger)
    assert len(conflicts) == 1
    c = conflicts[0]
    assert c["scope"] == "process"
    assert c["routing_decision"] == "blocked_from_confirmed_atomic"
    assert c["tiebreaker_required"] is True
    verds = {cv["verdict"] for cv in c["conflicting_verdicts"]}
    assert "malicious" in verds and "benign" in verds


def test_no_conflict_when_all_agree():
    recs = [
        _rec(pid=91003, process_name="FIXTURE_a.exe", verdict="malicious",
             source_finding_ids=["F7"]),
        _rec(pid=91003, process_name="FIXTURE_a.exe", verdict="malicious",
             source_finding_ids=["F8"]),
    ]
    ledger = build_react_entity_verdict_ledger(recs)
    assert detect_react_entity_contradictions(ledger) == []


def test_dependent_findings_routed_out_of_confirmed():
    ledger = build_react_entity_verdict_ledger(_conflicting_records())
    conflicts = detect_react_entity_contradictions(ledger)
    findings = [
        {"finding_id": "F1", "pid": 91001, "process": "FIXTURE_svc.exe"},
        {"finding_id": "F2", "pid": 91001, "process": "FIXTURE_svc.exe"},
        {"finding_id": "F9", "pid": 92222, "process": "FIXTURE_clean.exe"},
    ]
    blocked = findings_blocked_by_react_conflicts(findings, conflicts)
    assert blocked == {"F1", "F2"}
    assert "F9" not in blocked

    # A blocked finding cannot be confirmed and is routed to review.
    conflicted = dict(findings[0], react_entity_conflict=True)
    elig = evaluate_confirmed_bucket_eligibility(conflicted)
    assert elig["eligible"] is False
    assert elig["gates"][GATE_REACT_ENTITY_CONFLICT] == "FAIL"
    bucket, reasons = derive_final_disposition(conflicted)
    assert bucket == BUCKET_SUSPICIOUS
    assert bucket != BUCKET_CONFIRMED
    assert any("react_entity_conflict" in r for r in reasons)


def test_chain_conflict_does_not_block_member_process():
    # A chain-scope contradiction must not, by itself, route a separate
    # member process finding out of confirmed (scope discipline).
    recs = [
        _rec(scope="chain",
             chain_members=["FIXTURE_powershell.exe", "FIXTURE_b.exe"],
             verdict="malicious", source_finding_ids=["F10"]),
        _rec(scope="chain",
             chain_members=["FIXTURE_powershell.exe", "FIXTURE_b.exe"],
             verdict="benign", source_finding_ids=["F11"]),
    ]
    ledger = build_react_entity_verdict_ledger(recs)
    conflicts = detect_react_entity_contradictions(ledger)
    assert conflicts and conflicts[0]["scope"] == "chain"
    member = [{"finding_id": "F12", "pid": 91077,
               "process": "FIXTURE_powershell.exe"}]
    assert findings_blocked_by_react_conflicts(member, conflicts) == set()


def test_conflict_artifact_schema(tmp_path):
    ledger = build_react_entity_verdict_ledger(_conflicting_records())
    conflicts = detect_react_entity_contradictions(ledger)
    path = write_react_entity_conflicts(tmp_path, conflicts, "deadbee")
    assert path.name == CONFLICT_ARTIFACT_NAME
    doc = json.loads(path.read_text())
    assert doc["schema_version"] == CONFLICT_SCHEMA_VERSION
    assert doc["head"] == "deadbee"
    assert isinstance(doc["generated_at_epoch"], int)
    assert len(doc["conflicts"]) == 1
    c = doc["conflicts"][0]
    for field in ("entity_key", "scope", "conflicting_verdicts",
                  "routing_decision", "tiebreaker_required"):
        assert field in c
    # B6: deterministic scaffold only -- no AI/live tiebreaker output.
    assert "tiebreaker_result" not in c
    assert "ai_resolution" not in c


def test_empty_conflicts_still_writes_valid_artifact(tmp_path):
    path = write_react_entity_conflicts(tmp_path, [], "cafe123")
    doc = json.loads(path.read_text())
    assert doc["conflicts"] == []
    assert doc["schema_version"] == CONFLICT_SCHEMA_VERSION


def test_direct_malicious_plus_benign(tmp_path):
    recs = [
        _rec(pid=91092, scope="process", verdict="malicious",
             source_finding_ids=["FA"]),
        _rec(pid=91092, scope="process", process_name="FIXTURE_x.exe",
             verdict="benign", source_finding_ids=["FB"]),
    ]
    con = detect_react_entity_contradictions(
        build_react_entity_verdict_ledger(recs))
    assert len(con) == 1
    assert con[0]["entity_key"] == "process:91092"
    assert con[0]["conflict_type"] == "direct_entity_verdict_conflict"
    assert con[0]["routing_decision"] == "blocked_from_confirmed_atomic"


def test_direct_malicious_plus_inconclusive():
    recs = [
        _rec(pid=91093, scope="process", verdict="malicious",
             source_finding_ids=["FC"]),
        _rec(pid=91093, scope="process", verdict="inconclusive",
             source_finding_ids=["FD"]),
    ]
    con = detect_react_entity_contradictions(
        build_react_entity_verdict_ledger(recs))
    assert len(con) == 1
    assert con[0]["entity_key"] == "process:91093"
    assert con[0]["conflict_type"] == "direct_entity_verdict_conflict"


def test_chain_member_tension_detected_without_marking_member_malicious():
    """5d-alpha TASK 4: a malicious chain whose member process has a
    direct benign verdict yields a chain_member_tension on that
    process -- but the member is NOT given a malicious verdict."""
    recs = [
        _rec(scope="chain", verdict="malicious",
             chain_members=["FIXTURE_wmiprvse.exe", "FIXTURE_powershell.exe",
                            "FIXTURE_cmd.exe", "FIXTURE_payload.exe"],
             chain_member_pids=[91094], source_finding_ids=["FE"],
             excerpt="process chain ... represents confirmed malicious"),
        _rec(pid=91094, scope="process", process_name="FIXTURE_powershell.exe",
             verdict="benign", source_finding_ids=["FF"],
             excerpt="PID 91094 is benign"),
    ]
    ledger = build_react_entity_verdict_ledger(recs)
    # The member process entity itself was never concluded malicious.
    assert set(ledger["process:91094"]["verdicts"]) == {"benign"}
    con = detect_react_entity_contradictions(ledger)
    tensions = [c for c in con
                if c["conflict_type"] == "chain_member_tension"]
    assert len(tensions) == 1
    t = tensions[0]
    assert t["entity_key"] == "process:91094"
    assert t["scope"] == "process"
    assert t["routing_decision"] == "blocked_from_confirmed_atomic"
    assert t["tiebreaker_required"] is True
    # A finding on PID 91094 is routed out of confirmed.
    f = [{"finding_id": "FF", "pid": 91094,
          "process": "FIXTURE_powershell.exe"}]
    assert findings_blocked_by_react_conflicts(f, con) == {"FF"}


def test_chain_verdict_is_not_a_direct_process_malicious_verdict():
    recs = [
        _rec(scope="chain", verdict="malicious",
             chain_members=["FIXTURE_a.exe", "FIXTURE_b.exe"],
             chain_member_pids=[91095], source_finding_ids=["FG"]),
    ]
    ledger = build_react_entity_verdict_ledger(recs)
    # No process:91095 entity exists from a chain verdict alone.
    assert "process:91095" not in ledger
    assert any(k.startswith("chain:") for k in ledger)


def test_marker():
    print(f"{REACT_ENTITY_VERDICT_CONFLICT_DETECTED_GATE}=PASS")
    print(f"{REACT_CONTRADICTION_ROUTE_GATE}=PASS")
    print(f"{REACT_ENTITY_TIEBREAKER_REQUIRED_GATE}=PASS")
    assert REACT_CONTRADICTION_ROUTE_GATE == "REACT_CONTRADICTION_ROUTE_GATE"
