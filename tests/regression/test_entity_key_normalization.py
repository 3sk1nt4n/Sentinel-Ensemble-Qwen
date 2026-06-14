"""Slot 31F-alpha TASK 1 -- canonical entity key normalization.

ENTITY_KEY_NORMALIZATION_GATE. Synthetic fixtures only: PIDs
91000-99999, /synthetic paths, FIXTURE_* process names. No real
evidence value is referenced.
"""
from __future__ import annotations

from sift_sentinel.entities import (
    ENTITY_KEY_NORMALIZATION_GATE,
    canonical_entity_key,
    entity_scope_of,
    normalize_path,
    normalize_process_name,
)


def test_gate_identifier_stable():
    assert ENTITY_KEY_NORMALIZATION_GATE == "ENTITY_KEY_NORMALIZATION_GATE"


def test_normalize_path_is_case_and_separator_insensitive():
    a = normalize_path("C:\\Synthetic\\Temp\\FIXTURE_payload.exe")
    b = normalize_path("c:/synthetic//temp/fixture_payload.exe/")
    assert a == b == "c:/synthetic/temp/fixture_payload.exe"
    assert normalize_path(None) == ""
    assert normalize_path("   ") == ""


def test_normalize_process_name_strips_path_and_quotes():
    assert normalize_process_name(
        'C:\\Synthetic\\FIXTURE_svc.EXE') == "fixture_svc.exe"
    assert normalize_process_name('"FIXTURE_svc.exe"') == "fixture_svc.exe"
    assert normalize_process_name(None) == ""


def test_hash_scope_key():
    f = {
        "finding_id": "FIXTURE_001",
        "claims": [{"type": "hash", "sha256": "AABBCC", "filename": "x"}],
    }
    keys = canonical_entity_key(f)
    assert "hash:sha256:aabbcc" in keys
    assert entity_scope_of("hash:sha256:aabbcc") == "hash"


def test_process_key_uses_pid_identity_when_present():
    f = {"finding_id": "FIXTURE_002", "pid": 91234,
         "process": "FIXTURE_proc.exe", "claims": []}
    keys = canonical_entity_key(f)
    assert "process:91234:fixture_proc.exe" in keys
    assert entity_scope_of("process:91234:fixture_proc.exe") == "process"


def test_process_name_scope_when_pid_absent():
    f = {"finding_id": "FIXTURE_003",
         "claims": [{"type": "pid", "process": "FIXTURE_only.exe"}]}
    keys = canonical_entity_key(f)
    assert "process_name:fixture_only.exe" in keys


def test_network_scope_key_from_connection_claim():
    f = {
        "finding_id": "FIXTURE_004",
        "claims": [{
            "type": "connection", "proto": "TCP", "local_port": 4444,
            "foreign_addr": "10.9.9.9", "foreign_port": 80,
        }],
    }
    keys = canonical_entity_key(f)
    net = [k for k in keys if k.startswith("network:")]
    assert net == ["network:tcp:*:4444:10.9.9.9:80"]


def test_chain_signature_is_order_sensitive():
    fwd = {
        "finding_id": "FIXTURE_005", "is_synthesis": True,
        "claims": [
            {"type": "pid", "pid": 91001, "process": "FIXTURE_a.exe"},
            {"type": "pid", "pid": 91002, "process": "FIXTURE_b.exe"},
            {"type": "pid", "pid": 91003, "process": "FIXTURE_c.exe"},
        ],
    }
    rev = {
        "finding_id": "FIXTURE_006", "is_synthesis": True,
        "claims": [
            {"type": "pid", "pid": 91003, "process": "FIXTURE_c.exe"},
            {"type": "pid", "pid": 91002, "process": "FIXTURE_b.exe"},
            {"type": "pid", "pid": 91001, "process": "FIXTURE_a.exe"},
        ],
    }
    kf = [k for k in canonical_entity_key(fwd) if k.startswith("chain:")]
    kr = [k for k in canonical_entity_key(rev) if k.startswith("chain:")]
    assert kf and kr
    assert kf != kr  # A->B->C must differ from C->B->A


def test_chain_finding_does_not_emit_member_process_keys():
    f = {
        "finding_id": "FIXTURE_007", "is_synthesis": True,
        "claims": [
            {"type": "pid", "pid": 91010, "process": "FIXTURE_x.exe"},
            {"type": "pid", "pid": 91011, "process": "FIXTURE_y.exe"},
        ],
    }
    keys = canonical_entity_key(f)
    assert any(k.startswith("chain:") for k in keys)
    assert not any(k.startswith("process:") for k in keys)


def test_unknown_scope_falls_back_to_finding_id():
    f = {"finding_id": "FIXTURE_008", "claims": []}
    keys = canonical_entity_key(f)
    assert len(keys) == 1
    assert keys[0].startswith("unknown:")


def test_keys_are_sorted_and_deduplicated():
    f = {
        "finding_id": "FIXTURE_009",
        "artifact": "C:\\Synthetic\\a.exe, C:\\Synthetic\\a.exe",
        "claims": [{"type": "hash", "sha1": "DEAD"},
                   {"type": "hash", "sha1": "dead"}],
    }
    keys = canonical_entity_key(f)
    assert keys == sorted(keys)
    assert len(keys) == len(set(keys))
