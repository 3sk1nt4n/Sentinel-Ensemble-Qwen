"""FP-verdict routing fixes -- universal, no case values.
loopback-benign + per-entity benign propagation; conservative; default-inert.
"""
from sift_sentinel.analysis.fp_routing import (
    apply_fp_routing, loopback_only, has_independent_malice,
)
from sift_sentinel.analysis.disposition import (
    derive_final_disposition, BUCKET_BENIGN, BUCKET_SUSPICIOUS,
)


def _f(fid, **kw):
    d = {"finding_id": fid, "claims": []}
    d.update(kw)
    return d


def test_loopback_only_shape():
    assert loopback_only(_f("A", title="listener on 127.0.0.1:1900")) is True
    assert loopback_only(_f("B", title="connection to 10.0.0.5:445")) is False
    assert loopback_only(_f("C", title="127.0.0.1 and 203.0.113.9:443")) is False  # public peer
    assert loopback_only(_f("D", title="no ip here")) is False


def test_loopback_benign_is_flagged_and_routes_benign():
    f = _f("F056", title="staging network 127.0.0.1",
           react_conclusion={"is_false_positive": True, "verdict": "confirmed_benign"})
    n = apply_fp_routing([f])
    assert n == 1 and f.get("_fp_routing_benign") is True
    bucket, _ = derive_final_disposition(f)
    assert bucket == BUCKET_BENIGN


def test_entity_benign_propagation():
    # F043: process pid 6036 judged benign. F004: same pid, only a weak signal.
    benign = _f("F043", claims=[{"type": "pid", "pid": 6036, "process": "u.exe"}],
                react_conclusion={"is_false_positive": True})
    other = _f("F004", title="pid:6036 RWX region",
               claims=[{"type": "pid", "pid": 6036, "process": "u.exe"}])
    n = apply_fp_routing([benign, other])
    assert other.get("_fp_routing_benign") is True
    assert derive_final_disposition(other)[0] == BUCKET_BENIGN


def test_propagation_is_conservative_against_independent_malice():
    # a same-entity finding that has its OWN non-weak malicious signal is NOT buried
    benign = _f("B", claims=[{"type": "pid", "pid": 10, "process": "p.exe"}],
                react_conclusion={"is_false_positive": True})
    real = _f("R", claims=[{"type": "pid", "pid": 10, "process": "p.exe"}],
              malicious_semantic_signals=["ifeo_debugger_hijack"])
    apply_fp_routing([benign, real])
    assert real.get("_fp_routing_benign") is not True


def test_default_inert_without_flag():
    # a finding with NO flag routes exactly as before (the hook is inert)
    f = _f("X", title="t", severity="LOW", claims=[{"type": "pid", "pid": 1}])
    b1, _ = derive_final_disposition(f)
    assert "_fp_routing_benign" not in f
    assert b1 in (BUCKET_BENIGN, BUCKET_SUSPICIOUS, "inconclusive_unresolved",
                  "confirmed_malicious_atomic", "synthesis_narrative")


def test_propagation_picks_up_pid_from_text_not_just_claims():
    # mirrors the live F043 -> F004 case: the benign finding's OWN claim is a
    # different pid; the shared process pid appears only in its detail TEXT.
    benign = _f("F043", title="RunOnce startup chain",
                claims=[{"type": "pid", "pid": 7944, "process": "r.exe"}],
                description="PID 6036 (updater) is benign: legitimate signed updater.",
                react_conclusion={"is_false_positive": True})
    rwx = _f("F004", title="memory injection in updater",
             claims=[{"type": "pid", "pid": 6036, "process": "u.exe"}],
             description="RWX VAD PAGE_EXECUTE_READWRITE in updater (PID 6036)",
             malicious_semantic_signals=["rwx_memory_region_with_unusual_protection"])
    apply_fp_routing([benign, rwx])
    assert rwx.get("_fp_routing_benign") is True
    from sift_sentinel.analysis.disposition import derive_final_disposition, BUCKET_BENIGN
    assert derive_final_disposition(rwx)[0] == BUCKET_BENIGN
