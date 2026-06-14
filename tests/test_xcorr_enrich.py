"""XCORR: deterministic cross-artifact corroboration enrichment.

A finding's entity (file path / hash / service name) that the EvidenceDB
independently observed in 3+ artifact domains gets those producing tools
attached to its source_tools, so calibrate_confidence's existing
"3+ artifact types = HIGH" ceiling reflects evidence that already exists.

Universal: entities come from the finding's own structured claims; the
corroboration map is built per-run from the case's own EvidenceDB. Synthetic
values only (x.sys / q.sys, RFC-5737 IPs); keyed on structure, no case data.
"""
from __future__ import annotations

import copy

import pytest

from sift_sentinel.analysis.confidence import (
    TOOL_TO_ARTIFACT_TYPE,
    count_artifact_types,
)
from sift_sentinel.analysis.xcorr_enrich import enrich_findings_with_xcorr


# ── synthetic EvidenceDB mirroring the real build_typed_evidence_db shape ──

def _fact(fact_type, n, tool, **fields):
    f = {
        "fact_id": "%s-%07d" % (fact_type, n),
        "fact_type": fact_type,
        "fact_signature": "%s|%d|%s" % (fact_type, n, tool),
        "canonical_entity_id": fields.pop("ceid", "path:c:/windows/x.sys"),
        "entity_id": fields.pop("eid", "path:c:/windows/x.sys"),
        "source_tool": tool,
        "source_tools": [tool],
        "raw_excerpt": fields.pop("raw_excerpt", ""),
        "artifact": fields.pop("artifact", []),
        "confidence_hint": "observed",
        "merge_count": 1,
    }
    f.update(fields)
    return f


def _evdb(basename="x.sys"):
    """One driver entity present in 4 families via 4 distinct-domain tools.

    Mirrors the real run shape: MFT fact indexed by_path; registry fact
    indexed by_service_name (stem); the event-log fact carries the path only
    in a detail FIELD (event_log_fact has no by_path index in the real DB);
    the memory handle fact carries a \\Device\\...-prefixed name (never equal
    to the drive-letter path, only basename-matchable).
    """
    stem = basename.rsplit(".", 1)[0]
    full = "c:/windows/" + basename
    ev = _fact("event_log_fact", 1, "parse_event_logs",
               eid="event:7045", ceid="event:7045",
               details="A service was installed. Path: C:\\Windows\\" + basename)
    reg = _fact("registry_persistence_fact", 1, "parse_registry_persistence",
                eid="registry:hklm/system/controlset001/services/" + stem,
                ceid="registry:hklm/system/controlset001/services/" + stem,
                value_data="\\SystemRoot\\" + basename)
    mft = _fact("filesystem_timeline_fact", 1, "extract_mft_timeline",
                eid="path:" + full, ceid="path:" + full, path=full)
    hnd = _fact("handle_fact", 1, "vol_handles",
                eid="pid:412", ceid="pid:412",
                handle_name="\\Device\\HarddiskVolume2\\Windows\\" + basename)
    return {
        "typed_facts": {
            "event_log_fact": [ev],
            "registry_persistence_fact": [reg],
            "filesystem_timeline_fact": [mft],
            "handle_fact": [hnd],
        },
        "indexes": {
            "by_path": {full: [mft["fact_id"]]},
            "by_service_name": {stem: [reg["fact_id"]]},
            "by_hash": {},
        },
    }


def _finding(basename="x.sys"):
    return {
        "finding_id": "F001",
        "title": "suspicious kernel driver",
        "source_tools": ["parse_event_logs"],
        "claims": [
            {"type": "path", "path": "C:\\Windows\\" + basename},
        ],
        "confidence_level": "MEDIUM",
    }


_RECORDS = {
    "parse_event_logs": 100,
    "parse_registry_persistence": 14,
    "extract_mft_timeline": 5000,
    "vol_handles": 900,
}


# ── map completion (prerequisite: corroborating tools must count as types) ──

def test_tool_map_covers_registry_persistence_filescan_strings():
    assert TOOL_TO_ARTIFACT_TYPE.get("parse_registry_persistence") == "R"
    assert TOOL_TO_ARTIFACT_TYPE.get("vol_filescan") == "M"
    assert TOOL_TO_ARTIFACT_TYPE.get("run_strings") == "M"
    assert TOOL_TO_ARTIFACT_TYPE.get("vol_ldrmodules") == "M"
    assert TOOL_TO_ARTIFACT_TYPE.get("run_mftecmd") == "T"


def test_tool_map_existing_entries_unchanged():
    # additive completion only -- the original 15 entries keep their letters
    assert TOOL_TO_ARTIFACT_TYPE["parse_event_logs"] == "E"
    assert TOOL_TO_ARTIFACT_TYPE["extract_mft_timeline"] == "T"
    assert TOOL_TO_ARTIFACT_TYPE["vol_handles"] == "M"
    assert TOOL_TO_ARTIFACT_TYPE["vol_netscan"] == "N"
    assert TOOL_TO_ARTIFACT_TYPE["get_amcache"] == "A"


# ── enrichment ──────────────────────────────────────────────────────────

def test_single_source_finding_enriched_to_four_types(monkeypatch):
    monkeypatch.delenv("SIFT_XCORR", raising=False)
    f = _finding()
    out = enrich_findings_with_xcorr([f], _evdb(), tool_records=_RECORDS)
    tools = out[0]["source_tools"]
    assert set(tools) >= {"parse_event_logs", "parse_registry_persistence",
                          "extract_mft_timeline", "vol_handles"}
    assert count_artifact_types(tools) >= 3          # calibrator HIGH ceiling
    aud = out[0]["xcorr_corroboration"]
    assert set(aud["families"]) >= {"event_log_fact",
                                    "registry_persistence_fact",
                                    "filesystem_timeline_fact",
                                    "handle_fact"}
    assert "extract_mft_timeline" in aud["tools"]


def test_metamorphic_relabel_identical_shape(monkeypatch):
    monkeypatch.delenv("SIFT_XCORR", raising=False)
    a = enrich_findings_with_xcorr(
        [_finding("x.sys")], _evdb("x.sys"), tool_records=_RECORDS)[0]
    b = enrich_findings_with_xcorr(
        [_finding("q.sys")], _evdb("q.sys"), tool_records=_RECORDS)[0]
    assert sorted(a["source_tools"]) == sorted(b["source_tools"])
    assert sorted(a["xcorr_corroboration"]["families"]) == \
        sorted(b["xcorr_corroboration"]["families"])


def test_single_family_entity_untouched(monkeypatch):
    monkeypatch.delenv("SIFT_XCORR", raising=False)
    db = _evdb()
    db["typed_facts"] = {
        "filesystem_timeline_fact": db["typed_facts"]["filesystem_timeline_fact"],
    }
    db["indexes"]["by_service_name"] = {}
    f = _finding()
    before = copy.deepcopy(f)
    out = enrich_findings_with_xcorr([f], db, tool_records=_RECORDS)
    assert out[0]["source_tools"] == before["source_tools"]
    assert "xcorr_corroboration" not in out[0]


def test_two_type_entity_untouched_below_floor(monkeypatch):
    # mem+disk only (2 artifact types): enrichment must NOT fire -- it would
    # otherwise trigger the pre-existing 2-domain HIGH upgrade on 2 types.
    monkeypatch.delenv("SIFT_XCORR", raising=False)
    db = _evdb()
    for fam in ("event_log_fact", "registry_persistence_fact"):
        db["typed_facts"].pop(fam)
    db["indexes"]["by_service_name"] = {}
    f = _finding()
    f["source_tools"] = ["vol_handles"]
    before = copy.deepcopy(f)
    out = enrich_findings_with_xcorr([f], db, tool_records=_RECORDS)
    assert out[0]["source_tools"] == before["source_tools"]
    assert "xcorr_corroboration" not in out[0]


def test_kill_switch_off_is_noop(monkeypatch):
    monkeypatch.setenv("SIFT_XCORR", "0")
    f = _finding()
    before = copy.deepcopy(f)
    out = enrich_findings_with_xcorr([f], _evdb(), tool_records=_RECORDS)
    assert out[0] == before


def test_phantom_tool_filtered_by_tool_records(monkeypatch):
    # a corroborating tool with 0 measured records must not be attached
    # (mirrors the calibrator's B5 phantom filter)
    monkeypatch.delenv("SIFT_XCORR", raising=False)
    records = dict(_RECORDS)
    records["vol_handles"] = 0
    out = enrich_findings_with_xcorr([_finding()], _evdb(),
                                     tool_records=records)
    assert "vol_handles" not in out[0]["source_tools"]
    # remaining 3 families / 3 types still corroborate
    assert count_artifact_types(out[0]["source_tools"]) >= 3


def test_empty_evdb_noop(monkeypatch):
    monkeypatch.delenv("SIFT_XCORR", raising=False)
    f = _finding()
    before = copy.deepcopy(f)
    for db in ({}, None, {"typed_facts": {}}):
        out = enrich_findings_with_xcorr([f], db, tool_records=_RECORDS)
        assert out[0] == before


def test_short_or_extensionless_basename_never_scanned(monkeypatch):
    # a 1-char extensionless claim value must not basename-match across
    # arbitrary fact text (over-corroboration guard)
    monkeypatch.delenv("SIFT_XCORR", raising=False)
    f = _finding()
    f["claims"] = [{"type": "path", "path": "x"}]
    before = copy.deepcopy(f)
    out = enrich_findings_with_xcorr([f], _evdb(), tool_records=_RECORDS)
    assert out[0]["source_tools"] == before["source_tools"]
