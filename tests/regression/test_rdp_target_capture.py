"""Regression: capture the RDP outbound lateral-movement target.

Two coupled fixes, both dataset-agnostic (token shape only, no host literals):

1. Extraction (parse_rdp_artifacts.normalize_evtx_event): RDPClient
   ClientActiveXCore events use a Name/Value idiom -- the host *label*
   ("Server Name") lands in ``Name`` (matched by _EVTX_HOST_KEYS) and the real
   destination FQDN in ``Value``. The parser previously stored the label as
   ``host_or_target``; it must prefer the host-shaped ``Value``.

2. Scoring (candidate_observations._score_fact): an RDP fact whose target is an
   FQDN (not an IP) must be credited ``rdp_target_reference`` instead of
   suppressed ``rdp_context_without_target``. It stays remote_access_context
   (never validation_ready) -- this widens recall without loosening precision.

Tests assert properties, never specific dataset values.
"""

from __future__ import annotations

import importlib

import pytest


# ── Extraction: Name/Value idiom ────────────────────────────────────────

def _norm():
    import sift_sentinel.tools.parse_rdp_artifacts as p

    return importlib.reload(p)


def test_namevalue_idiom_prefers_host_shaped_value_fqdn():
    p = _norm()
    event = {
        "EventID": 1024,
        "TimeCreated": "2024-03-15T09:10:00.000Z",
        "EventRecordID": 1,
        "EventData": {"Name": "Server Name", "Value": "host-a.sub.example.local"},
    }
    rec = p.normalize_evtx_event(event, "rdp_client_operational", "c.evtx")
    assert rec is not None
    # The FQDN target, not the "Server Name" label.
    assert rec["host_or_target"] == "host-a.sub.example.local"


def test_namevalue_idiom_prefers_host_shaped_value_ip():
    p = _norm()
    event = {
        "EventID": 1024, "TimeCreated": "2024-03-15T09:10:00.000Z",
        "EventRecordID": 2,
        "EventData": {"Name": "ServerAddress", "Value": "10.1.2.3"},
    }
    rec = p.normalize_evtx_event(event, "rdp_client_operational", "c.evtx")
    assert rec["host_or_target"] == "10.1.2.3"


def test_namevalue_idiom_keeps_label_when_value_not_host_shaped():
    """A non-host Value (e.g. a Disconnect Reason text) must NOT override."""
    p = _norm()
    event = {
        "EventID": 1026, "TimeCreated": "2024-03-15T09:10:00.000Z",
        "EventRecordID": 3,
        "EventData": {"Name": "Disconnect Reason", "Value": "The local computer ended"},
    }
    rec = p.normalize_evtx_event(event, "rdp_client_operational", "c.evtx")
    # Not a host -> left as the label (still no false target).
    assert rec["host_or_target"] == "Disconnect Reason"


def test_connectionname_schema_unaffected():
    """The existing ConnectionName schema must keep working unchanged."""
    p = _norm()
    event = {
        "EventID": 1024, "TimeCreated": "2024-03-15T09:10:00.000Z",
        "EventRecordID": 4,
        "EventData": {"ConnectionName": "target-host-1.example.local"},
    }
    rec = p.normalize_evtx_event(event, "rdp_client_operational", "c.evtx")
    assert rec["host_or_target"] == "target-host-1.example.local"


def test_looks_like_host_rejects_labels_and_accepts_targets():
    p = _norm()
    assert p._looks_like_host("pivot-host.corp.example.lan") is True
    assert p._looks_like_host("203.0.113.7") is True
    assert p._looks_like_host("Server Name") is False
    assert p._looks_like_host("Disconnect Reason") is False
    assert p._looks_like_host("") is False
    assert p._looks_like_host(None) is False


# ── Scoring: FQDN target credited, stays context ────────────────────────

def _co():
    import sift_sentinel.analysis.candidate_observations as co

    return importlib.reload(co)


def _rdp_fact(host_or_target, raw_excerpt=""):
    return {
        "fact_id": "rdp_artifact_fact-1",
        "fact_type": "rdp_artifact_fact",
        "source_tool": "parse_rdp_artifacts",
        "record_ref": "parse_rdp_artifacts#1",
        "host_or_target": host_or_target,
        "raw_excerpt": raw_excerpt,
    }


def test_fqdn_target_is_credited_rdp_target_reference():
    co = _co()
    score, signals, suppressions = co._score_fact(
        _rdp_fact("pivot-host.corp.example.lan")
    )
    assert "rdp_target_reference" in signals
    assert "rdp_context_without_target" not in suppressions


def test_value_payload_fqdn_credited_when_field_is_label():
    co = _co()
    # host_or_target is a label but raw_excerpt carries the Value= FQDN.
    score, signals, _ = co._score_fact(
        _rdp_fact("Server Name", raw_excerpt="EventID=1024 Name=Server Name Value=pivot-host.corp.example.lan")
    )
    assert "rdp_target_reference" in signals


def test_no_target_still_suppressed():
    co = _co()
    _, signals, suppressions = co._score_fact(
        _rdp_fact("", raw_excerpt="EventID=40 TimeCreated=2020-01-01T00:00:00Z")
    )
    assert "rdp_target_reference" not in signals
    assert "rdp_context_without_target" in suppressions


def test_fqdn_rdp_candidate_is_context_not_validation_ready():
    co = _co()
    # Two facts for the same FQDN target (e.g. connect + reconnect) group into
    # one entity and clear the candidate score floor, mirroring the real
    # outbound case. A lone reference (score 25) is correctly thin-suppressed.
    raw = "EventID=1024 Name=Server Name Value=pivot-host.corp.example.lan"
    f1 = _rdp_fact("pivot-host.corp.example.lan", raw_excerpt=raw)
    f2 = dict(_rdp_fact("pivot-host.corp.example.lan", raw_excerpt=raw))
    f2["fact_id"] = "rdp_artifact_fact-2"
    f2["record_ref"] = "parse_rdp_artifacts#2"
    db = {"typed_facts": {"rdp_artifact_fact": [f1, f2]}}
    payload = co.build_candidate_observations(db)
    cands = payload["candidates"]
    rdp = [c for c in cands if "rdp_target_reference" in (c.get("signals") or [])]
    assert rdp, "FQDN RDP target (>=2 facts) should form a candidate"
    # Stays context; never promoted to validation_ready by this widening.
    assert all(c.get("candidate_type") == "remote_access_context" for c in rdp)
    assert not any(c.get("validation_ready") for c in rdp)
