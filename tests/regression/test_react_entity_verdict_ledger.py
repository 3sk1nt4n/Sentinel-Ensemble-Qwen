"""Slot 31E-DB.5d GROUP B TASK B3 -- REACT_ENTITY_VERDICT_LEDGER_GATE.

Verdict records fold into a per-entity ledger keyed by canonical entity
identity. The ledger preserves distinct verdicts, source finding ids,
evidence refs and trimmed excerpts. Dataset-agnostic: synthetic PIDs
91000-99999, /synthetic paths.
"""
from __future__ import annotations

from sift_sentinel.react_verdicts import (
    REACT_ENTITY_VERDICT_LEDGER_GATE,
    build_react_entity_verdict_ledger,
    canonical_entity_key,
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


def test_same_pid_and_name_collapse_to_one_entity():
    recs = [
        _rec(pid=91001, process_name="FIXTURE_svc.exe", verdict="malicious",
             source_finding_ids=["F1"], excerpt="CONCLUDED -- bad"),
        _rec(pid=91001, process_name="FIXTURE_svc.exe", verdict="malicious",
             source_finding_ids=["F2"], excerpt="CONCLUDED -- also bad"),
    ]
    ledger = build_react_entity_verdict_ledger(recs)
    assert len(ledger) == 1
    key = canonical_entity_key(recs[0])
    entry = ledger[key]
    assert entry["scope"] == "process"
    assert entry["verdicts"] == ["malicious"]
    assert sorted(entry["source_finding_ids"]) == ["F1", "F2"]
    assert len(entry["excerpts"]) == 2


def test_distinct_verdicts_accumulate_per_entity():
    recs = [
        _rec(file="/synthetic/p.bin", verdict="malicious",
             source_finding_ids=["F3"], evidence_refs=["tc-1"]),
        _rec(file="/synthetic/p.bin", verdict="benign",
             source_finding_ids=["F4"], evidence_refs=["tc-2"]),
    ]
    ledger = build_react_entity_verdict_ledger(recs)
    key = canonical_entity_key(recs[0])
    entry = ledger[key]
    assert entry["scope"] == "file"
    assert set(entry["verdicts"]) == {"malicious", "benign"}
    assert set(entry["evidence_refs"]) == {"tc-1", "tc-2"}


def test_pid_absent_uses_process_name_key():
    rec = _rec(process_name="FIXTURE_only_name.exe", verdict="inconclusive")
    key = canonical_entity_key(rec)
    assert key == "process_name:fixture_only_name.exe"
    ledger = build_react_entity_verdict_ledger([rec])
    assert key in ledger


def test_records_without_verdict_are_skipped():
    ledger = build_react_entity_verdict_ledger([_rec(verdict=None)])
    assert ledger == {}


def test_pid_collision_regardless_of_name():
    """5d-alpha TASK 1: a no-name malicious verdict and a named benign
    verdict for the SAME pid must collapse to ONE process:<pid> entity
    carrying both verdicts (names are aliases, not key parts)."""
    recs = [
        _rec(pid=91091, process_name=None, verdict="malicious",
             source_finding_ids=["F1"], excerpt="PID 91091 is malicious"),
        _rec(pid=91091, process_name="FIXTURE_vendorx_srv.exe",
             verdict="benign", source_finding_ids=["F2"],
             excerpt="PID 91091 (FIXTURE_vendorx_srv.exe) is benign"),
    ]
    ledger = build_react_entity_verdict_ledger(recs)
    assert list(ledger) == ["process:91091"], list(ledger)
    entry = ledger["process:91091"]
    assert set(entry["verdicts"]) == {"malicious", "benign"}
    assert entry["process_aliases"] == ["FIXTURE_vendorx_srv.exe"]
    assert entry["pids"] == [91091]
    assert entry["display_name"] == "FIXTURE_vendorx_srv.exe"


def test_named_and_unnamed_same_pid_single_key():
    a = canonical_entity_key(_rec(pid=8128, process_name="OUTLOOK.EXE"))
    b = canonical_entity_key(_rec(pid=8128, process_name=None))
    assert a == b == "process:8128"


def test_marker():
    print(f"{REACT_ENTITY_VERDICT_LEDGER_GATE}=PASS")
    assert REACT_ENTITY_VERDICT_LEDGER_GATE == "REACT_ENTITY_VERDICT_LEDGER_GATE"
