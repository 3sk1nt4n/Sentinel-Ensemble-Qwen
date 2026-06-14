"""Blanket entity-corroboration: a validated finding pulls corroborating
typed-fact refs from EVERY fact_type that shares one of its entities, not
just the process/file facts its claim-types map to. Dataset-agnostic --
keyed on the finding's own normalized entities; public sample IP only."""
from __future__ import annotations

from sift_sentinel.validation.validator import _entity_corroborating_refs
from sift_sentinel.validation.typed_validator import (
    normalize_ip, normalize_path, normalize_registry,
)


def _ed():
    ipk = normalize_ip("8.8.8.8")
    regk = normalize_registry("HKLM\\Software\\Acme\\Run\\payload")
    pathk = normalize_path("C:\\Users\\Public\\payload.exe")
    typed = {
        "process_fact": [{"fact_id": "proc-1", "fact_type": "process_fact",
                          "pid": 1337}],
        "memory_injection_fact": [{"fact_id": "mij-1",
                                   "fact_type": "memory_injection_fact",
                                   "pid": 1337}],
        "network_connection_fact": [{"fact_id": "net-1",
                                     "fact_type": "network_connection_fact",
                                     "foreignaddr": "8.8.8.8"}],
        "registry_persistence_fact": [{"fact_id": "reg-1",
                                       "fact_type":
                                       "registry_persistence_fact"}],
        "lnk_execution_fact": [{"fact_id": "lnk-1",
                                "fact_type": "lnk_execution_fact"}],
    }
    indexes = {
        "by_pid": {"1337": ["proc-1", "mij-1"]},
        "by_ip": {ipk: ["net-1"]},
        "by_registry_path": {regk: ["reg-1"]},
        "by_path": {pathk: ["lnk-1"]},
    }
    return {"typed_facts": typed, "indexes": indexes}


def test_corroboration_spans_every_entity_sharing_fact_type():
    finding = {"claims": [
        {"type": "pid", "pid": 1337},
        {"type": "connection", "foreign_addr": "8.8.8.8"},
        {"type": "path", "value": "HKLM\\Software\\Acme\\Run\\payload"},
        {"type": "artifact", "artifact": "C:\\Users\\Public\\payload.exe"},
    ]}
    refs = _entity_corroborating_refs(finding, _ed())
    by_type = {r["fact_type"] for r in refs}
    assert "memory_injection_fact" in by_type
    assert "network_connection_fact" in by_type
    assert "registry_persistence_fact" in by_type
    assert "lnk_execution_fact" in by_type
    for r in refs:
        assert r["fact_id"] and r["via"]
        assert r["relation"] == "entity_corroboration"


def test_corroboration_empty_without_evidence_db():
    assert _entity_corroborating_refs({"claims": [{"type": "pid",
                                                   "pid": 1337}]}, None) == []


def test_corroboration_ignores_unmatched_entities():
    assert _entity_corroborating_refs(
        {"claims": [{"type": "pid", "pid": 999999}]}, _ed()) == []
