"""Defect A: the deterministic confirmed-section claim renderer must render a value
that AGREES with the claim's own type label. A type-agnostic field order rendered a
pid-claim's process name under 'pid:' and a connection-claim's stray pid under
'connection:' -- producing 'pid: vendorx_srv.exe' / 'connection: 214656' on the
flagship confirmed finding. Universal: keyed on claim type + field names, no case data.
"""
from sift_sentinel.reporting.deterministic_confirmed_section import (
    _claim_value,
    _claims_summary,
)


def test_pid_claim_renders_pid_not_process():
    c = {"type": "pid", "pid": 214656, "process": "vendorx_srv.exe"}
    assert _claim_value(c) == "214656"
    assert _claims_summary({"claims": [c]}) == ["pid: 214656"]


def test_process_claim_renders_process_name():
    c = {"type": "process", "process": "vendorx_srv.exe", "pid": 214656}
    assert _claim_value(c) == "vendorx_srv.exe"


def test_connection_claim_renders_endpoint_not_pid():
    c = {"type": "connection", "dst_ip": "172.16.5.25", "port": 5682, "pid": 214656}
    assert _claim_value(c) == "172.16.5.25:5682"


def test_connection_claim_without_endpoint_does_not_show_bare_pid():
    # the exact malformed claim that produced 'connection: 214656' in the live report
    c = {"type": "connection", "pid": 214656}
    v = _claim_value(c)
    # must NOT render the bare pid as if it were a connection endpoint
    assert v != "214656"
    # acceptable: a labelled pid, or empty (then the line renders just 'connection')
    assert v in ("", "pid 214656")


def test_hash_claim_prefers_strong_hash():
    c = {"type": "hash", "sha256": "deadbeef", "value": "x"}
    assert _claim_value(c) == "deadbeef"


def test_unknown_type_falls_back_to_generic_order():
    # no per-type mapping -> first populated generic field still works
    c = {"type": "whatever", "path": "C:/x.exe"}
    assert _claim_value(c) == "C:/x.exe"
