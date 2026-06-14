from sift_sentinel.correction.self_correct import (
    normalize_sc_claim,
    normalize_sc_claims,
    normalize_sc_finding,
)


def test_normalize_sc_claim_missing_type_becomes_unrecognized():
    out = normalize_sc_claim({"claim": "some unsupported narrative"})
    assert out["type"] == "unrecognized"
    assert "some unsupported narrative" in out["text"]


def test_normalize_sc_claim_alias_type_fields():
    out = normalize_sc_claim({"claim_type": "network_connection", "description": "pid to ip"})
    assert out["type"] == "network_connection"
    assert out["text"] == "pid to ip"


def test_normalize_sc_claim_non_dict_becomes_unstructured():
    out = normalize_sc_claim("raw malformed claim")
    assert out["type"] == "unstructured"
    assert out["text"] == "raw malformed claim"


def test_normalize_sc_finding_never_requires_claim_type():
    finding = {"id": "synthetic", "claims": [{"description": "no type here"}]}
    out = normalize_sc_finding(finding)
    assert out["claims"][0]["type"] == "unrecognized"
    assert out["claims"][0]["text"] == "no type here"


def test_normalize_sc_claims_handles_none_and_single_dict():
    assert normalize_sc_claims(None) == []
    out = normalize_sc_claims({"kind": "pid", "value": 1234})
    assert out[0]["type"] == "pid"
