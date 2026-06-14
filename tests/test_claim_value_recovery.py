"""Universal value-recovery: a value-bearing claim whose 'value' is missing but
whose datum sits in another field (registry_path/url/event_id/name...) is recovered
instead of dropped as 'no recognized claim types'. Keyed on field PRESENCE + shape,
never case data -- all values here are generic placeholders.
"""
from sift_sentinel.validation.normalize_claims import normalize_claims


def _norm_one(claim):
    out = normalize_claims([{"finding_id": "F", "claims": [claim]}])
    return out[0]["claims"][0]


def test_registry_path_field_recovered_to_value():
    c = _norm_one({"type": "path", "name": "svc_persistence",
                   "registry_path": "hklm/system/controlset001/services/example/imagepath"})
    assert c["type"] == "path"
    assert c["value"] == "hklm/system/controlset001/services/example/imagepath"


def test_key_field_recovered():
    c = _norm_one({"type": "path",
                   "key": "hklm/system/controlset002/control/safeboot/alternateshell"})
    assert c["value"].endswith("safeboot/alternateshell")


def test_event_id_field_retypes_to_event_log():
    c = _norm_one({"type": "path", "name": "logon_notify", "event_id": "7001"})
    assert c["type"] == "event_log"
    assert "7001" in c["value"]


def test_url_field_recovered():
    c = _norm_one({"type": "path", "url": "http://staging.example-host.net/a"})
    assert c["value"] == "http://staging.example-host.net/a"


def test_existing_value_never_clobbered():
    c = _norm_one({"type": "path", "value": "C:/Windows/System32/real.exe",
                   "name": "decoy", "registry_path": "hklm/decoy"})
    assert c["value"] == "C:/Windows/System32/real.exe"     # untouched


def test_pid_claim_not_value_recovered():
    # identity-keyed type: name must NOT be promoted to value
    c = _norm_one({"type": "pid", "pid": 1234, "name": "explorer.exe"})
    assert not c.get("value")                                # left alone
