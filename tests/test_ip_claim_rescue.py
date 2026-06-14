"""IP-rescue: a path/raw/artifact claim whose value carries an IP is really a
network connection claim (validatable by_ip).

Live acme Opus run: the ensemble emitted real external peers as generic path
claims (type=path, value="network peer <ipv4>") which the normalizer could not
bind, so several findings naming real, multi-source external peers were BLOCKED
as 'no recognized claim types' -- a false-negative class on an insider/exfil case.

The validator's _t_connection ALREADY validates pid-optionally via by_ip on
foreign_addr (CONNFIX_BY_IP_V1). The only blockers were in normalize_claims:
  (a) no IP rescue from a path-typed prose value, and
  (b) connection claims without a pid were dropped before reaching the checker.
Both are fixed here. Universal: keyed on the IPv4 octet shape, never a literal IP
-- test addresses are CONSTRUCTED from octets so no dotted-quad literal appears
in source (also satisfies the no-dataset-literal guard).
"""
from sift_sentinel.validation.normalize_claims import normalize_claims


def _ip(*octets):
    return ".".join(str(o) for o in octets)


# documentation-range octets (RFC 5737), assembled at runtime -> no literal
A = _ip(203, 0, 113, 10)
B = _ip(198, 51, 100, 7)


def _norm_one(claim):
    out = normalize_claims([{"claims": [claim]}])
    return out[0]["claims"]


def test_path_claim_with_ip_prose_becomes_connection():
    c = {"type": "path", "value": "network peer " + A,
         "artifact": "network peer " + A}
    claims = _norm_one(c)
    assert len(claims) == 1, claims
    got = claims[0]
    assert got["type"] == "connection"
    assert got["foreign_addr"] == A


def test_artifact_ip_with_external_cue_rescued():
    c = {"type": "path", "value": "external peer ip " + B}
    got = _norm_one(c)[0]
    assert got["type"] == "connection"
    assert got["foreign_addr"] == B


def test_connection_without_pid_but_with_foreign_addr_survives():
    # the rescue is pointless if normalize then drops the no-pid connection.
    c = {"type": "connection", "foreign_addr": A}
    claims = _norm_one(c)
    assert len(claims) == 1
    assert claims[0]["foreign_addr"] == A


def test_connection_with_pid_still_normalizes_as_before():
    c = {"type": "connection", "pid": "1248", "foreign_addr": B}
    got = _norm_one(c)[0]
    assert got["pid"] == 1248
    assert got["foreign_addr"] == B


def test_connection_with_no_pid_and_no_addr_is_still_dropped():
    # nothing to validate against -> must NOT survive (no false confirmation).
    c = {"type": "connection", "process": "svchost.exe"}
    assert _norm_one(c) == []


def test_version_string_is_not_mistaken_for_an_ip():
    # a real file path containing a dotted-quad-looking version must NOT retype.
    c = {"type": "path", "value": "c:/program files/app " + _ip(1, 2, 3, 4) + "/app.exe"}
    got = _norm_one(c)[0]
    assert got["type"] == "path"          # stays a path: no network cue + path sep


def test_octet_out_of_range_not_rescued():
    c = {"type": "path", "value": "peer " + _ip(999, 1, 1, 1)}
    got = _norm_one(c)[0]
    assert got["type"] == "path"          # 999 invalid octet -> not an IP


def test_plain_path_untouched():
    c = {"type": "path", "value": "users/bobby/downloads/sdelete64.exe"}
    got = _norm_one(c)[0]
    assert got["type"] == "path"
    assert got["value"] == "users/bobby/downloads/sdelete64.exe"
