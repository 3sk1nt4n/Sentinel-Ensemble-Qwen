"""Slot 31E-DB.1 - Typed EvidenceDB compiler tests.

Gates covered:
  COMPILE / DEFAULT_IMPORT / SYNTHETIC_TYPED_EVIDENCEDB /
  REAL_STATE_REPLAY / per-artifact typed-fact gates /
  LOSSY_COMPILATION_TELEMETRY / COVERAGE_RECONCILIATION /
  FACT_SIGNATURE_NORMALIZATION / NO_API_SIDE_TEST / NO_LIVE_SIDE_TEST

The real-state replay locates the most recent /tmp/sift-sentinel-run-*
state dir with a populated tool_outputs/ folder. If none exists the
replay test is skipped (CI / fresh checkout) -- it never fabricates.
"""

from __future__ import annotations

import glob
import json
import os
from pathlib import Path

import pytest

from sift_sentinel.analysis.evidence_db import (
    FACT_TYPES,
    INDEX_NAMES,
    build_typed_evidence_db,
    fact_signature,
    normalize_ip,
    normalize_path,
)

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "sift_sentinel"


# ── helpers ──────────────────────────────────────────────────────────────


def _reports_state_dir():
    """Return a report-referenced state directory, if any.

    Dataset-agnostic:
    - reads generated reports/log references only;
    - does not encode case names, hosts, IPs, users, PIDs, or findings;
    - returns None so callers can fall back to latest temp state.
    """
    import re
    from pathlib import Path

    rx = re.compile(r"/tmp/sift-sentinel-run-[A-Za-z0-9_.-]+")
    search_roots = [Path("reports"), Path("logs")]

    candidates = []
    for root in search_roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".md", ".txt", ".json", ".log", ".out"}:
                continue
            candidates.append(path)

    candidates.sort(key=lambda x: x.stat().st_mtime, reverse=True)

    for path in candidates[:250]:
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue
        for match in rx.findall(text):
            sd = Path(match)
            if sd.exists() and sd.is_dir():
                return str(sd)

    return None


def _latest_state_dir() -> str | None:
    candidates = sorted(
        glob.glob("/tmp/sift-sentinel-run-*"),
        key=os.path.getmtime,
        reverse=True,
    )
    for d in candidates:
        if glob.glob(os.path.join(d, "tool_outputs", "*.json")):
            return d
    return None


def _load_state(sd: str) -> dict:
    out = {}
    for f in glob.glob(os.path.join(sd, "tool_outputs", "*.json")):
        with open(f) as fh:
            out[os.path.basename(f)[:-5]] = json.load(fh)
    return out


# ── DEFAULT_IMPORT_GATE ──────────────────────────────────────────────────

def test_default_import_gate():
    import sift_sentinel.analysis.evidence_db as m

    assert hasattr(m, "build_typed_evidence_db")
    assert m.VERSION == "31E-DB.1"
    assert set(FACT_TYPES) == set(
        m.build_typed_evidence_db({})["typed_facts"].keys()
    )


# ── SYNTHETIC_TYPED_EVIDENCEDB_GATE ──────────────────────────────────────

def _synthetic_outputs() -> dict:
    return {
        "vol_pstree": {"record_count": 2, "output": [
            {"PID": 4, "PPID": 0, "ImageFileName": "System",
             "CreateTime": "2018-08-30T13:51:58+00:00", "Path": None},
            {"PID": 500, "PPID": 4, "ImageFileName": "evil.exe",
             "CreateTime": "2018-09-01T01:02:03+00:00",
             "Path": "C:\\Temp\\evil.exe"},
        ]},
        "vol_netscan": {"record_count": 1, "output": [
            {"PID": 500, "Owner": "evil.exe", "LocalAddr": "10.0.0.5",
             "LocalPort": 4444, "ForeignAddr": "203.0.113.9",
             "ForeignPort": 443, "Proto": "TCPv4",
             "State": "ESTABLISHED"},
        ]},
        "vol_malfind": {"record_count": 1, "output": [
            {"PID": 500, "Process": "evil.exe",
             "Protection": "PAGE_EXECUTE_READWRITE", "Tag": "VadS",
             "Start VPN": 123},
        ]},
        "get_amcache": {"record_count": 1, "output": {"entries": [
            {"path": "C:\\Temp\\evil.exe", "sha1": "ABC123",
             "first_run": "2018-09-01T01:00:00"},
        ]}},
        "extract_mft_timeline": {"record_count": 1, "output": {"events": [
            {"path": "/Temp/evil.exe", "filename": "evil.exe",
             "si_created": "2018-09-01T01:00:00Z", "action": "exists"},
        ]}},
        "parse_registry_persistence": {"record_count": 1, "records": [
            {"registry_path": "HKLM\\SYSTEM\\CurrentControlSet\\Run",
             "value_name": "Evil", "value_data": "C:\\Temp\\evil.exe",
             "persistence_type": "run_key", "hive_type": "SYSTEM",
             "service_name": None},
        ]},
        "parse_scheduled_tasks_disk": {"record_count": 1, "records": [
            {"task_name": "EvilTask", "task_path": "\\EvilTask",
             "enabled": True, "hidden": False, "author": "atk",
             "actions": [{"type": "Exec",
                          "execute": "C:\\Temp\\evil.exe"}]},
        ]},
        "parse_event_logs": {"record_count": 1, "output": [
            {"EventID": 4624, "TimeCreated": "2018-09-01 01:00:00",
             "Provider": "Security", "Channel": "Security",
             "Message": "logon"},
        ]},
        "vol_svcscan": {"record_count": 1, "output": [
            {"Name": "EvilSvc", "Binary": "C:\\Temp\\evil.exe",
             "Dll": None, "State": "SERVICE_RUNNING",
             "Start": "SERVICE_AUTO_START", "PID": 500},
        ]},
        "extract_network_iocs": {"record_count": 2, "records": [
            {"type": "ipv4", "value": "203.0.113.9", "port": 443,
             "classification": "suspicious"},
            {"type": "domain", "value": "bad.example",
             "classification": "unknown", "port": None},
        ]},
    }


def test_synthetic_typed_evidencedb_gate():
    db = build_typed_evidence_db(_synthetic_outputs(),
                                 {"hashes": {}, "hidden_pids": {1}})

    assert db["version"] == "31E-DB.1"
    assert set(db["typed_facts"].keys()) == set(FACT_TYPES)
    assert set(db["indexes"].keys()) == set(INDEX_NAMES)
    assert db["legacy_reference_set_passthrough"]["hidden_pids"] == ["1"]

    tf = db["typed_facts"]
    assert len(tf["process_fact"]) == 2
    assert len(tf["process_relationship_fact"]) >= 1
    assert len(tf["network_connection_fact"]) == 1
    assert len(tf["memory_injection_fact"]) == 1
    # SLOT 31AP: _c_mft routing fixed - MFT now emits filesystem_timeline_fact,
    # file_execution_fact is amcache-only (semantically correct).
    assert len(tf["file_execution_fact"]) == 1  # amcache only
    assert len(tf["filesystem_timeline_fact"]) == 1  # mft
    assert len(tf["registry_persistence_fact"]) == 1
    assert len(tf["scheduled_task_fact"]) == 1
    assert len(tf["event_log_fact"]) == 1
    assert len(tf["service_fact"]) == 1
    assert len(tf["network_ioc_fact"]) == 2

    # Every fact carries the mandated provenance fields.
    for facts in tf.values():
        for f in facts:
            for key in ("fact_id", "fact_type", "fact_signature",
                        "source_tool", "source_record_index",
                        "confidence_hint", "raw_excerpt"):
                assert key in f, key
            assert len(f["fact_signature"]) == 40

    # Indexes resolve to real fact_ids.
    all_ids = {f["fact_id"] for fs in tf.values() for f in fs}
    for idx in db["indexes"].values():
        for fids in idx.values():
            for fid in fids:
                assert fid in all_ids

    assert "by_pid" in db["indexes"] and "500" in db["indexes"]["by_pid"]
    assert "203.0.113.9" in db["indexes"]["by_ip"]
    assert "eviltask" in db["indexes"]["by_task_name"]
    assert "evilsvc" in db["indexes"]["by_service_name"]
    assert "4624" in db["indexes"]["by_event_id"]


# ── FACT_SIGNATURE_NORMALIZATION_GATE ────────────────────────────────────

def test_fact_signature_normalization_gate():
    # Path normalization: backslash/case/trailing-slash/quotes collapse.
    assert (normalize_path('"C:\\Temp\\Evil.EXE"')
            == normalize_path("c:/temp//evil.exe/"))
    assert normalize_path("A\\B\\C") == "a/b/c"

    # IP canonicalization: whitespace + IPv6 zero-compression collapse to
    # one canonical form; junk yields None (strict, no fabrication).
    assert normalize_ip("  203.0.113.9 ") == "203.0.113.9"
    assert (normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001")
            == normalize_ip("2001:db8::1"))
    assert normalize_ip("203.000.113.009") is None  # leading zeros: junk
    assert normalize_ip("not-an-ip") is None

    # Two registry records differing only by slash direction / case must
    # collapse to one fact (same signature).
    base = {
        "record_count": 2,
        "records": [
            {"registry_path": "HKLM\\SYSTEM\\Run", "value_name": "X",
             "value_data": "C:\\a\\b.exe", "persistence_type": "run_key",
             "hive_type": "SYSTEM"},
            {"registry_path": "hklm/system/run", "value_name": "x",
             "value_data": "C:/a//b.exe", "persistence_type": "run_key",
             "hive_type": "SYSTEM"},
        ],
    }
    db = build_typed_evidence_db({"parse_registry_persistence": base})
    assert len(db["typed_facts"]["registry_persistence_fact"]) == 1
    cov = db["coverage"]["per_tool"]["parse_registry_persistence"]
    assert cov["compiled_record_count"] == 2  # both compiled
    assert cov["emitted_fact_count"] == 1     # one deduped fact
    assert cov["reconciliation_ok"] is True

    sig = fact_signature("x", "ENT", ["A", None, 1])
    assert sig == fact_signature("x", "ENT", ["A", "", "1"])


# ── LOSSY_COMPILATION_TELEMETRY_GATE ─────────────────────────────────────

def test_lossy_compilation_telemetry_gate():
    outputs = {
        "vol_pstree": {"record_count": 3, "output": [
            {"PID": 1, "PPID": 0, "ImageFileName": "ok.exe"},
            {"PID": None, "ImageFileName": "broken.exe"},   # dropped
            {"PID": 2, "ImageFileName": ""},                # dropped
        ]},
    }
    db = build_typed_evidence_db(outputs)
    cov = db["coverage"]["per_tool"]["vol_pstree"]
    assert cov["record_count"] == 3
    assert cov["compiled_record_count"] == 1
    assert cov["dropped_record_count"] == 2
    assert cov["dropped_reasons"].get("missing_pid_or_name") == 2
    assert cov["reconciliation_ok"] is True


# ── COVERAGE_RECONCILIATION_GATE ─────────────────────────────────────────

def test_coverage_reconciliation_gate_synthetic():
    db = build_typed_evidence_db(_synthetic_outputs())
    for tool, cov in db["coverage"]["per_tool"].items():
        assert (
            cov["record_count"]
            == cov["compiled_record_count"] + cov["dropped_record_count"]
        ), f"reconciliation failed for {tool}: {cov}"
        assert cov["reconciliation_ok"] is True
    assert db["coverage"]["totals"]["all_reconciled"] is True


def test_error_envelope_is_fully_dropped_and_reconciled():
    db = build_typed_evidence_db({
        "vol_malfind": {"record_count": 5, "error": "vol crashed"},
    })
    cov = db["coverage"]["per_tool"]["vol_malfind"]
    assert cov["compiled_record_count"] == 0
    assert cov["dropped_record_count"] == 5
    assert cov["dropped_reasons"]["error_envelope"] == 5
    assert cov["reconciliation_ok"] is True


# ── NO_API_SIDE_TEST_GATE / NO_LIVE_SIDE_TEST_GATE ───────────────────────

def test_no_api_no_live_side_test_gate():
    """The compiler module must be pure: no network, subprocess, model
    SDKs, or live-run imports anywhere in its source."""
    src = (SRC_ROOT / "analysis" / "evidence_db.py").read_text()
    banned = (
        "import requests", "import httpx", "urllib.request",
        "subprocess", "anthropic", "openai", "google.generativeai",
        "socket.", "os.system", "popen", "run_pipeline",
        "coordinator", "ANTHROPIC_API_KEY",
    )
    low = src.lower()
    for token in banned:
        assert token.lower() not in low, f"banned token in module: {token}"


# ── REAL_STATE_REPLAY_GATE (+ per-artifact typed-fact gates) ─────────────

@pytest.fixture(scope="module")
def real_db():
    sd = _latest_state_dir()
    if sd is None:
        pytest.skip("no populated /tmp/sift-sentinel-run-* state dir")
    return sd, build_typed_evidence_db(_load_state(sd))


def test_real_state_replay_gate(real_db):
    """Replay gate must be dataset-agnostic.

    No fixed per-dataset thresholds. No exact fact-type assumptions for a tool
    unless the compiler contract itself guarantees that name. The gate checks
    what matters for A+/zero-fake behavior:
    - EvidenceDB contains typed facts.
    - Data-producing tools are not silently dropped for missing compiler coverage.
    - Any data-producing tool with compiler coverage has attribution/compiled facts
      or an explicit suppression/not-applicable reason.
    """
    from sift_sentinel.analysis import evidence_db

    sd, db = real_db
    coverage = db.get("coverage", {})
    totals = coverage.get("totals", {})
    tc = totals.get("fact_type_counts", {})
    per = coverage.get("per_tool", {})

    assert sum(int(v or 0) for v in tc.values()) > 0

    compilers = getattr(evidence_db, "_TOOL_COMPILERS", {})

    def _n(value):
        try:
            return int(value or 0)
        except Exception:
            return 0

    # Hard fail: no data-producing tool should be silently dropped for missing
    # compiler coverage.
    violations = coverage.get("violations") or db.get("violations") or []
    silent_drops = [
        v for v in violations
        if isinstance(v, dict)
        and v.get("kind") == "missing_compiler_for_nonempty_tool"
    ]
    assert not silent_drops, silent_drops

    # Dynamic per-tool coverage: if the replay says a compiler-backed tool
    # produced records, require some compiled/attributed output, not a specific
    # hardcoded fact-type name from one dataset.
    reviewed = 0
    for tool, info in per.items():
        if not isinstance(info, dict):
            continue

        produced = max(
            _n(info.get("raw_record_count")),
            _n(info.get("input_record_count")),
            _n(info.get("record_count")),
            _n(info.get("source_record_count")),
        )

        attributed = max(
            _n(info.get("attributed_fact_count")),
            _n(info.get("fact_count")),
            _n(info.get("compiled_fact_count")),
            _n(info.get("output_fact_count")),
        )

        status = str(
            info.get("status")
            or info.get("outcome")
            or info.get("disposition")
            or ""
        ).lower()

        explicitly_nonproducing = any(
            word in status
            for word in ("not_applicable", "suppressed", "skipped", "no_records")
        )

        if produced > 0 and tool in compilers:
            reviewed += 1
            assert attributed > 0 or explicitly_nonproducing, (
                f"{tool} produced {produced} record(s) and has compiler coverage "
                f"but attributed/compiled zero facts without explicit suppression: {info}"
            )

    assert reviewed > 0



def test_A_process_fact_schema_and_source_merge():
    outputs = {
        "vol_pstree": {"record_count": 1, "output": [
            {"PID": 12345, "PPID": 67890, "ImageFileName": "evil.exe",
             "Path": "C:\\Temp\\evil.exe", "Cmd": "evil.exe -run",
             "CreateTime": "2018-09-01T01:02:03+00:00",
             "ExitTime": None},
        ]},
        "vol_psscan": {"record_count": 1, "output": [
            {"PID": 12345, "PPID": 67890, "ImageFileName": "evil.exe",
             "Path": "C:\\Temp\\evil.exe",
             "CreateTime": "2018-09-01T01:02:03+00:00"},
        ]},
    }
    db = build_typed_evidence_db(outputs)
    pf = db["typed_facts"]["process_fact"]
    # Same PID/name/path/createtime -> one merged fact, not two.
    f = next(x for x in pf if x["pid"] == 12345)
    assert f["pid"] == 12345 and isinstance(f["pid"], int)
    assert f["canonical_entity_id"] == "pid:12345"
    assert set(f["source_tools"]) == {"vol_pstree", "vol_psscan"}
    assert any("vol_pstree#" in r for r in f["record_refs"])
    assert any("vol_psscan#" in r for r in f["record_refs"])
    assert sorted(f["source_record_indices"]) == [0]
    # First-class fields, not only raw_excerpt.
    assert f["process_name"] == "evil.exe"
    assert f["image_name"] == "evil.exe"
    assert f["path"] == "c:/temp/evil.exe"
    assert f["cmdline"] == "evil.exe -run"
    assert f["parent_pid"] == 67890
    assert f["create_time"]
    # Merge telemetry: psscan is the merging tool.
    per = db["coverage"]["per_tool"]
    assert per["vol_psscan"]["dedup_merged_count"] >= 1
    assert per["vol_pstree"]["attributed_fact_count"] >= 1
    assert per["vol_psscan"]["attributed_fact_count"] >= 1


# ── Test B: process_relationship_fact schema ─────────────────────────────

def test_B_process_relationship_fact_schema():
    outputs = {"vol_pstree": {"record_count": 1, "output": [
        {"PID": 12345, "PPID": 67890, "ImageFileName": "evil.exe"},
    ]}}
    db = build_typed_evidence_db(outputs)
    rels = db["typed_facts"]["process_relationship_fact"]
    assert len(rels) == 1
    r = rels[0]
    assert r["pid"] == 12345 and isinstance(r["pid"], int)
    assert r["parent_pid"] == 67890 and isinstance(r["parent_pid"], int)
    assert r["child_entity_id"] == "pid:12345"
    assert r["parent_entity_id"] == "pid:67890"
    assert r["canonical_entity_id"] == "pid:12345->pid:67890"
    assert r["process_name"] == "evil.exe"
    assert "source_tools" in r and r["source_tools"] == ["vol_pstree"]
    assert r["record_refs"] == ["vol_pstree#0"]


# ── Test C: real-state replay via reports/run_*.json state_dir ───────────

def test_C_real_state_replay_via_reports_state_dir():
    sd = _reports_state_dir() or _latest_state_dir()
    if sd is None:
        pytest.skip("no resolvable state_dir with tool_outputs")
    state = _load_state(sd)
    db = build_typed_evidence_db(state)

    raw_pstree = state.get("vol_pstree", {}).get("output", [])
    raw_pids = {r["PID"] for r in raw_pstree if r.get("PID") is not None}
    assert raw_pids, "fixture has no pstree PIDs"

    pf = db["typed_facts"]["process_fact"]
    pf_pids = {f["pid"] for f in pf}
    # Every raw pstree PID surfaces as a first-class int pid.
    assert raw_pids.issubset(pf_pids)
    assert all(isinstance(f["pid"], int) for f in pf if f["pid"] is not None)

    # Each raw pstree PID has >=1 process_fact carrying vol_pstree
    # attribution (psscan may add a distinct fact for the same PID when
    # its CreateTime differs -- that is correct, not lost attribution).
    facts_by_pid: dict = {}
    for f in pf:
        facts_by_pid.setdefault(f["pid"], []).append(f)
    for pid in raw_pids:
        group = facts_by_pid[pid]
        assert any(
            "vol_pstree" in f["source_tools"]
            or any("vol_pstree#" in r for r in f["record_refs"])
            for f in group
        ), f"PID {pid} has no vol_pstree-attributed process_fact"

    for r in db["typed_facts"]["process_relationship_fact"]:
        assert isinstance(r["pid"], int)
        assert isinstance(r["parent_pid"], int)

    ps = db["coverage"]["per_tool"]["vol_pstree"]
    assert ps["compiled_record_count"] == 129
    assert ps["dropped_record_count"] == 0
    assert ps["attributed_fact_count"] >= 129
    for tool, cov in db["coverage"]["per_tool"].items():
        assert (
            cov["record_count"]
            == cov["compiled_record_count"] + cov["dropped_record_count"]
        ), f"{tool}: {cov}"
    assert db["coverage"]["totals"]["all_reconciled"] is True


# ── Test D: no API / no live ─────────────────────────────────────────────

def test_D_no_api_no_live(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
              "GOOGLE_API_KEY"):
        monkeypatch.delenv(k, raising=False)

    def _boom(*a, **k):  # any socket use = live network attempt
        raise AssertionError("network access attempted in pure compiler")

    import socket as _socket
    monkeypatch.setattr(_socket, "socket", _boom)

    outputs = _synthetic_outputs()
    db1 = build_typed_evidence_db(outputs)
    db2 = build_typed_evidence_db(outputs)
    # Pure + deterministic: identical output across runs, no env/network.
    assert json.dumps(db1, sort_keys=True) == json.dumps(
        db2, sort_keys=True)
    assert db1["coverage"]["totals"]["all_reconciled"] is True
