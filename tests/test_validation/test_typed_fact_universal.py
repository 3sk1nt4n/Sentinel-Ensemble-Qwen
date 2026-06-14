"""Universal entity-keyed typed checker (typed_fact) -- agnostic mechanism guard.
Synthetic, obviously-fake facts only (no real-case IOC/path/answer-key value):
asserts the checker confirms a typed fact for an entity the claim names, abstains
when absent, and never fabricates a MISMATCH."""
from sift_sentinel.validation.typed_validator import (
    TypedEvidenceDB, typed_check_claim, TYPED_SUPPORTED_CLAIM_TYPES,
)
def _edb():
    return {
        "typed_facts": {
            "registry_persistence_fact": [{"fact_id": "r1", "fact_type": "registry_persistence_fact",
                "registry_path": "hklm\\software\\synthetic\\run\\sample"}],
            "memory_injection_fact": [{"fact_id": "m1", "fact_type": "memory_injection_fact", "pid": 4242}],
            "network_ioc_fact": [{"fact_id": "n1", "fact_type": "network_ioc_fact", "ip": "198.51.100.7"}],
        },
        "indexes": {
            "by_registry_path": {"hklm\\software\\synthetic\\run\\sample": ["r1"]},
            "by_pid": {"4242": ["m1"]},
            "by_ip": {"198.51.100.7": ["n1"]},
        },
    }
def test_supported_type_registered():
    assert "typed_fact" in TYPED_SUPPORTED_CLAIM_TYPES
def test_registry_entity_match():
    r = typed_check_claim({"type": "typed_fact", "fact_type": "registry_persistence_fact",
        "value": "HKLM\\Software\\Synthetic\\Run\\Sample"}, TypedEvidenceDB(_edb()))
    assert r is not None and r[0] == "MATCH"
def test_pid_entity_match():
    r = typed_check_claim({"type": "typed_fact", "fact_type": "memory_injection_fact", "pid": "4242"},
        TypedEvidenceDB(_edb()))
    assert r is not None and r[0] == "MATCH"
def test_ip_entity_match():
    r = typed_check_claim({"type": "typed_fact", "fact_type": "network_ioc_fact", "ip": "198.51.100.7"},
        TypedEvidenceDB(_edb()))
    assert r is not None and r[0] == "MATCH"
def test_absent_entity_abstains():
    r = typed_check_claim({"type": "typed_fact", "fact_type": "registry_persistence_fact",
        "value": "HKLM\\Software\\Synthetic\\Run\\DoesNotExist"}, TypedEvidenceDB(_edb()))
    assert r is None
def test_wrong_fact_type_for_present_entity_abstains():
    r = typed_check_claim({"type": "typed_fact", "fact_type": "service_fact", "pid": "4242"},
        TypedEvidenceDB(_edb()))
    assert r is None
