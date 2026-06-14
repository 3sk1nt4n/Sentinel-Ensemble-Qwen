"""Entity-benign propagation must NOT clear a finding that carries its own
EXTERNAL egress. A benign verdict on one finding adjudicated THAT behavior;
a different finding on the same PID showing a public external peer is distinct
network behavior the donor verdict never examined -- propagating benign onto it
could mask real exfiltration from a sensitive process. Conservative direction:
it stays for the analyst (honest failure > wrong answer).

Universal: public-IPv4 octet shape only (loopback/RFC1918/unspecified excluded),
no process-name list. Synthetic findings + TEST-NET addresses only.
Kill-switch SIFT_FP_PROP_EGRESS_VETO=0.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.fp_routing import apply_fp_routing  # noqa: E402


def _benign_donor(pid=4242):
    return {"finding_id": "B1",
            "title": "synthetic activity in fakeproc.exe (PID %d)" % pid,
            "claims": [{"type": "pid", "pid": pid}],
            "react_conclusion": {"is_false_positive": True,
                                 "conclusion": "benign"}}


def _receiver(pid=4242, ip=None):
    desc = "fakeproc.exe (PID %d) observed" % pid
    if ip:
        desc += " connecting to external peer %s" % ip
    return {"finding_id": "R1", "title": "synthetic", "description": desc,
            "claims": [{"type": "pid", "pid": pid}]}


def test_propagation_still_works_without_egress():
    donor, recv = _benign_donor(), _receiver()
    apply_fp_routing([donor, recv])
    assert recv.get("_fp_routing_benign") is True
    assert recv.get("_fp_routing_reason") == "entity_benign_propagation"


def test_external_egress_vetoes_propagation():
    donor, recv = _benign_donor(), _receiver(ip="203.0.113.99")
    apply_fp_routing([donor, recv])
    assert not recv.get("_fp_routing_benign")      # stays for the analyst


def test_loopback_peer_does_not_veto():
    donor, recv = _benign_donor(), _receiver(ip="127.0.0.1")
    apply_fp_routing([donor, recv])
    assert recv.get("_fp_routing_benign") is True


def test_rfc1918_peer_does_not_veto():
    donor, recv = _benign_donor(), _receiver(ip="192.168.7.7")
    apply_fp_routing([donor, recv])
    assert recv.get("_fp_routing_benign") is True


def test_kill_switch_restores_legacy(monkeypatch):
    monkeypatch.setenv("SIFT_FP_PROP_EGRESS_VETO", "0")
    donor, recv = _benign_donor(), _receiver(ip="203.0.113.99")
    apply_fp_routing([donor, recv])
    assert recv.get("_fp_routing_benign") is True
