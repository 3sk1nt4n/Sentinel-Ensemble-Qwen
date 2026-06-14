"""Slot 31X-lite -- early drift + EvidenceDB coverage gate.

All synthetic fixtures are dataset-agnostic and use RFC5737
documentation IPs (never real IOCs). No live/API calls. The real-state
replay (test 12) reads only already-persisted local run artifacts.
"""

import glob
import json
import os
import subprocess

import pytest

from sift_sentinel.analysis.evidence_db import build_typed_evidence_db
from sift_sentinel.validation.reference_set import build_reference_set
from sift_sentinel.analysis.drift_gate import (
    build_tool_surface_snapshot,
    validate_tool_surface_snapshot,
    build_evidencedb_coverage_snapshot,
    validate_evidencedb_coverage_snapshot,
    evidence_baseline_match,
    run_31x_lite_gate,
)

_DOC_IP = "203.0.113.7"          # RFC5737 TEST-NET-3 -- not a real IOC
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


def _errors(verdicts):
    return [v for v in verdicts if v.get("severity") == "error"]


# ── Synthetic tool-surface fixtures ─────────────────────────────────────

def _clean_surface_kwargs():
    reg = {"vol_pstree": (None, "memory"),
           "parse_event_logs": (None, "standalone"),
           "run_mftecmd": (None, "ez_tools")}
    caps = {"vol_pstree", "parse_event_logs", "run_mftecmd"}
    hv = {"run_mftecmd"}
    res = {"run_mftecmd"}
    return dict(registry=reg, capability_names=caps,
                high_value_tools=hv, resolver_names=res)


# 1. Synthetic tool-surface pass.
def test_01_tool_surface_pass():
    snap = build_tool_surface_snapshot(**_clean_surface_kwargs())
    assert snap["registry_tool_count"] == 3
    assert snap["registered_tool_names"] == [
        "parse_event_logs", "run_mftecmd", "vol_pstree"]
    assert validate_tool_surface_snapshot(snap) == []


# 2. Synthetic missing capability fails.
def test_02_missing_capability_fails():
    kw = _clean_surface_kwargs()
    kw["capability_names"] = {"vol_pstree", "run_mftecmd"}  # drop one
    snap = build_tool_surface_snapshot(**kw)
    assert "parse_event_logs" in snap["missing_capabilities"]
    errs = _errors(validate_tool_surface_snapshot(snap))
    assert any(e["kind"] == "registered_tool_missing_capability"
               for e in errs)


# 3. Synthetic high-value missing from resolver contract fails.
def test_03_high_value_missing_resolver_fails():
    kw = _clean_surface_kwargs()
    kw["resolver_names"] = set()  # high-value tool has no resolver
    snap = build_tool_surface_snapshot(**kw)
    assert snap["high_value_without_resolver"] == ["run_mftecmd"]
    errs = _errors(validate_tool_surface_snapshot(snap))
    assert any(e["kind"] == "high_value_tool_missing_resolver"
               for e in errs)


def test_03b_resolver_without_high_value_fails():
    kw = _clean_surface_kwargs()
    kw["resolver_names"] = {"run_mftecmd", "ghost_tool"}
    snap = build_tool_surface_snapshot(**kw)
    assert snap["resolver_without_high_value"] == ["ghost_tool"]
    errs = _errors(validate_tool_surface_snapshot(snap))
    assert any(e["kind"] == "resolver_without_high_value" for e in errs)


def test_03c_high_value_not_registered_fails():
    kw = _clean_surface_kwargs()
    kw["high_value_tools"] = {"run_mftecmd", "not_registered_tool"}
    kw["resolver_names"] = {"run_mftecmd", "not_registered_tool"}
    snap = build_tool_surface_snapshot(**kw)
    assert "not_registered_tool" in snap["missing_high_value_tools"]
    errs = _errors(validate_tool_surface_snapshot(snap))
    assert any(e["kind"] == "high_value_tool_missing_from_surface"
               for e in errs)


# ── Synthetic EvidenceDB fixtures ───────────────────────────────────────

def _good_tool_outputs():
    return {
        "vol_pstree": {"output": [
            {"PID": 4, "ImageFileName": "System", "PPID": 0,
             "Path": "", "CreateTime": "2026-01-02 03:00:00"},
            {"PID": 800, "ImageFileName": "services.exe", "PPID": 4,
             "Path": r"C:\Windows\System32\services.exe",
             "CreateTime": "2026-01-02 03:04:00"},
        ]},
        "vol_netscan": {"output": [
            {"PID": 800, "Proto": "TCP", "LocalAddr": "10.0.0.5",
             "LocalPort": 50544, "ForeignAddr": _DOC_IP,
             "ForeignPort": 4444, "State": "ESTABLISHED",
             "Owner": "services.exe"},
        ]},
        "vol_malfind": {"output": [
            {"PID": 800, "Process": "services.exe",
             "Protection": "PAGE_EXECUTE_READWRITE",
             "Start VPN": "0x1000", "End VPN": "0x2000", "Tag": "VadS"},
        ]},
        "parse_event_logs": {"records": [
            {"EventID": 4624, "Provider": "Security",
             "Channel": "Security", "TimeCreated": "2026-01-02 03:05",
             "Message": "logon"},
        ]},
        "parse_registry_persistence": {"records": [
            {"registry_path": r"HKLM\Software\Run", "value_name": "x",
             "value_data": r"C:\t\x.exe", "persistence_type": "run_key",
             "hive_type": "SOFTWARE"},
        ]},
        "parse_scheduled_tasks_disk": {"records": [
            {"task_name": "Updater", "task_path": r"\Updater",
             "actions": [{"execute": r"C:\t\x.exe"}],
             "enabled": True, "hidden": False, "author": "a"},
        ]},
        "extract_network_iocs": {"records": [
            {"type": "ip", "value": _DOC_IP, "port": 4444,
             "classification": "c2_candidate"},
        ]},
        "get_amcache": {"output": [
            {"path": r"C:\t\x.exe", "sha1": "a" * 40,
             "first_run": "2026-01-02 03:01:00"},
        ]},
    }


# 4. Synthetic EvidenceDB coverage pass.
def test_04_evidencedb_coverage_pass():
    to = _good_tool_outputs()
    evdb = build_typed_evidence_db(to, build_reference_set(to))
    snap = build_evidencedb_coverage_snapshot(
        evdb, to, evidence_hashes={"mem": "h1"})
    assert snap["missing_coverage_for_nonempty_compiled_tools"] == []
    assert snap["zero_typed_fact_families_for_nonempty_source_tools"] == []
    assert snap["reconciliation_failures"] == []
    assert _errors(validate_evidencedb_coverage_snapshot(snap)) == []


# 5. raw vol_malfind > 0 but memory_injection_fact == 0 fails.
def test_05_malfind_records_no_injection_fact_fails():
    to = _good_tool_outputs()
    # Strip PID so the malfind compiler drops every record (0 facts)
    # while record_count stays > 0.
    to["vol_malfind"] = {"output": [
        {"Process": "x.exe", "Protection": "RW",
         "Start VPN": "0x1", "Tag": "VadS"}]}
    evdb = build_typed_evidence_db(to, build_reference_set(to))
    snap = build_evidencedb_coverage_snapshot(evdb, to)
    fams = [z["fact_family"] for z in snap[
        "zero_typed_fact_families_for_nonempty_source_tools"]]
    assert "memory_injection_fact" in fams
    errs = _errors(validate_evidencedb_coverage_snapshot(snap))
    assert any(e["kind"] == "zero_typed_fact_family"
               and e["details"]["fact_family"] == "memory_injection_fact"
               for e in errs)


# 6. Registry / task / event / network sources > 0 with zero typed
#    facts each fail.
@pytest.mark.parametrize("tool,family,bad_records", [
    ("parse_registry_persistence", "registry_persistence_fact",
     [{"no_registry_path": 1}]),
    ("parse_scheduled_tasks_disk", "scheduled_task_fact",
     [{"no_task_name": 1}]),
    ("parse_event_logs", "event_log_fact", [{"no_event_id": 1}]),
    ("vol_netscan", "network_connection_fact",
     [{"Proto": "TCP", "State": "LISTEN"}]),
])
def test_06_source_records_zero_family_fails(tool, family, bad_records):
    to = _good_tool_outputs()
    key = "records" if tool.startswith("parse_") else "output"
    to[tool] = {key: bad_records}
    evdb = build_typed_evidence_db(to, build_reference_set(to))
    snap = build_evidencedb_coverage_snapshot(evdb, to)
    errs = _errors(validate_evidencedb_coverage_snapshot(snap))
    assert any(e["kind"] == "zero_typed_fact_family"
               and e["details"]["fact_family"] == family
               for e in errs), f"{family} not flagged for {tool}"


# 7. Synthetic coverage reconciliation failure fails.
def test_07_reconciliation_failure_fails():
    snap = {
        "version": "31X-lite",
        "evidence_hashes": {},
        "typed_counts": {"process_fact": 1},
        "per_tool": {"vol_pstree": {"reconciliation_ok": False,
                                    "record_count": 5}},
        "raw_tool_record_counts": {"vol_pstree": 5},
        "missing_coverage_for_nonempty_compiled_tools": [],
        "zero_typed_fact_families_for_nonempty_source_tools": [],
        "reconciliation_failures": ["vol_pstree"],
    }
    errs = _errors(validate_evidencedb_coverage_snapshot(snap))
    assert any(e["kind"] == "coverage_reconciliation_failure"
               and e["details"]["tool"] == "vol_pstree" for e in errs)


# 8. Same-evidence regression > configured threshold fails.
def test_08_same_evidence_regression_fails():
    prev = {"evidence_hashes": {"mem": "h1"},
            "typed_counts": {"network_connection_fact": 100}}
    cur = {"evidence_hashes": {"mem": "h1"},
           "typed_counts": {"network_connection_fact": 80},
           "per_tool": {}, "raw_tool_record_counts": {},
           "missing_coverage_for_nonempty_compiled_tools": [],
           "zero_typed_fact_families_for_nonempty_source_tools": [],
           "reconciliation_failures": []}
    matched, reason = evidence_baseline_match(
        cur["evidence_hashes"], prev)
    assert matched and reason == "all_hashes_match"
    errs = _errors(validate_evidencedb_coverage_snapshot(
        cur, previous_snapshot=prev))
    assert any(e["kind"] == "typed_count_regression"
               and e["details"]["fact_family"] == "network_connection_fact"
               for e in errs)


# 9. Different-evidence previous snapshot regression is skipped.
def test_09_different_evidence_regression_skipped():
    prev = {"evidence_hashes": {"mem": "OLD"},
            "typed_counts": {"memory_injection_fact": 7}}
    cur = {"evidence_hashes": {"mem": "NEW"},
           "typed_counts": {"memory_injection_fact": 0},
           "per_tool": {}, "raw_tool_record_counts": {},
           "missing_coverage_for_nonempty_compiled_tools": [],
           "zero_typed_fact_families_for_nonempty_source_tools": [],
           "reconciliation_failures": []}
    matched, reason = evidence_baseline_match(
        cur["evidence_hashes"], prev)
    assert not matched and reason == "hash_mismatch:mem"
    verdicts = validate_evidencedb_coverage_snapshot(
        cur, previous_snapshot=prev)
    assert _errors(verdicts) == []
    assert any(v["kind"] == "regression_check_skipped"
               and v["severity"] == "warning" for v in verdicts)


# 10. Same-evidence threshold boundary passes (exactly at budget).
def test_10_threshold_boundary_passes():
    prev = {"evidence_hashes": {"d": "h"},
            "typed_counts": {"event_log_fact": 25000}}
    cur = {"evidence_hashes": {"d": "h"},
           "typed_counts": {"event_log_fact": 22500},  # -10% exactly
           "per_tool": {}, "raw_tool_record_counts": {},
           "missing_coverage_for_nonempty_compiled_tools": [],
           "zero_typed_fact_families_for_nonempty_source_tools": [],
           "reconciliation_failures": []}
    errs = _errors(validate_evidencedb_coverage_snapshot(
        cur, previous_snapshot=prev))
    assert errs == []
    # One record below the boundary must fail.
    cur["typed_counts"]["event_log_fact"] = 22499
    errs2 = _errors(validate_evidencedb_coverage_snapshot(
        cur, previous_snapshot=prev))
    assert any(e["kind"] == "typed_count_regression" for e in errs2)


# 11. Same-evidence deterministic family regression fails (0.0 budget).
def test_11_deterministic_family_regression_fails():
    prev = {"evidence_hashes": {"d": "h"},
            "typed_counts": {"memory_injection_fact": 7}}
    cur = {"evidence_hashes": {"d": "h"},
           "typed_counts": {"memory_injection_fact": 6},
           "per_tool": {}, "raw_tool_record_counts": {},
           "missing_coverage_for_nonempty_compiled_tools": [],
           "zero_typed_fact_families_for_nonempty_source_tools": [],
           "reconciliation_failures": []}
    errs = _errors(validate_evidencedb_coverage_snapshot(
        cur, previous_snapshot=prev))
    assert any(e["kind"] == "typed_count_regression"
               and e["details"]["fact_family"] == "memory_injection_fact"
               for e in errs)


# 12. Real-state replay -- latest non-meta reports/run_*.json -> its
#     state_dir under /tmp/sift-sentinel-run-*. Must PASS, no API.
def test_12_real_state_replay():
    runs = sorted(
        (f for f in glob.glob(os.path.join(_REPO, "reports", "run_*.json"))
         if not f.endswith("_meta.json")),
        key=os.path.getmtime)
    if not runs:
        pytest.skip("no non-meta reports/run_*.json available")
    state_dir = json.load(open(runs[-1])).get("state_dir")
    if not state_dir or not os.path.isdir(state_dir):
        pytest.skip(f"state_dir absent: {state_dir}")
    to_dir = os.path.join(state_dir, "tool_outputs")
    if not os.path.isdir(to_dir):
        pytest.skip("state_dir has no tool_outputs/")
    tool_outputs = {}
    for fp in glob.glob(os.path.join(to_dir, "*.json")):
        with open(fp) as fh:
            tool_outputs[os.path.basename(fp)[:-5]] = json.load(fh)
    if not tool_outputs:
        pytest.skip("no persisted tool outputs to replay")
    sha_path = os.path.join(state_dir, "sha256_pre.json")
    evidence_hashes = (json.load(open(sha_path))
                       if os.path.isfile(sha_path) else {})
    evdb = build_typed_evidence_db(
        tool_outputs, build_reference_set(tool_outputs))
    env = run_31x_lite_gate(
        evidence_db=evdb, tool_outputs=tool_outputs,
        evidence_hashes=evidence_hashes,
        tool_surface_kwargs=_clean_surface_kwargs())
    assert env["status"] == "pass", env["violations"]
    assert env["evidencedb_coverage"]["reconciliation_failures"] == []


# 13. Dirty scope gate -- only the in-scope files may be dirty.
def test_13_dirty_scope_gate():
    allowed = {
        "src/sift_sentinel/analysis/drift_gate.py",
        "run_pipeline.py",
        "tests/test_validation/test_31x_lite_drift_gate.py",
    }
    out = subprocess.run(
        ["git", "status", "--porcelain"], cwd=_REPO,
        capture_output=True, text=True, check=True).stdout
    dirty = {line[3:].strip() for line in out.splitlines() if line.strip()}
    extra = dirty - allowed
    assert not extra, f"out-of-scope dirty files: {sorted(extra)}"


# 14. Postcommit clean tree gate -- after the slot commit lands the
#     working tree is clean. Pre-commit this is a scope subset check.
def test_14_postcommit_clean_tree_gate():
    out = subprocess.run(
        ["git", "status", "--porcelain"], cwd=_REPO,
        capture_output=True, text=True, check=True).stdout
    if not out.strip():
        return  # committed: clean tree -- gate satisfied
    allowed = {
        "src/sift_sentinel/analysis/drift_gate.py",
        "run_pipeline.py",
        "tests/test_validation/test_31x_lite_drift_gate.py",
    }
    dirty = {line[3:].strip() for line in out.splitlines() if line.strip()}
    assert dirty <= allowed, f"unexpected dirty files: {sorted(dirty)}"
