"""A deterministic atomic detection is never a synthesis narrative.

XCORR enriches a real behavioural finding (e.g. an SRUM egress outlier) with
cross-artifact corroboration, so it can cite many source tools. The
report-layer label _classify_finding_type marks any finding with >=6 source
tools 'composite_narrative', which is_synthesis_finding then treats as a
strong synthesis signal -- demoting the egress finding out of the confirmed
bucket into synthesis. A finding emitted deterministically with a registered
malicious_semantic is atomic by construction and must route normally.
Universal: keyed on the deterministic-emission markers, no case data.
"""
from __future__ import annotations

from sift_sentinel.analysis.disposition import (
    derive_final_disposition,
    is_synthesis_finding,
)


def _egress_finding():
    # the real F054 shape: deterministic egress outlier, 16 source tools,
    # mislabelled composite_narrative by the >=6-tools heuristic.
    return {
        "finding_id": "F054",
        "title": "data exfiltration egress outlier: path:program files/x/msedge.exe",
        "finding_type": "composite_narrative",
        "evidence_type": "disk",
        "confidence_level": "HIGH",
        "severity": "HIGH",
        "deterministic_finding": True,
        "deterministic_kind": "candidate_semantic",
        "malicious_semantic_signals": ["srum_egress_outlier"],
        "source_tools": ["get_amcache", "parse_event_logs", "parse_prefetch",
                         "run_appcompatcacheparser", "run_jlecmd", "run_lecmd",
                         "run_srumecmd", "sleuthkit_tsk_recover", "vol_cmdline",
                         "vol_filescan", "vol_getsids", "vol_handles",
                         "vol_privileges", "vol_psscan", "vol_pstree", "vol_psxview"],
        "claims": [{"type": "path", "value": "program files/x/msedge.exe"},
                   {"type": "srum_usage", "value": "64410159574"}],
    }


def test_deterministic_semantic_finding_is_not_synthesis():
    is_syn, sig = is_synthesis_finding(_egress_finding())
    assert is_syn is False, sig


def test_real_narrative_still_synthesis():
    # an AI-written attack-chain narrative (no deterministic marker) still routes
    f = {"finding_id": "N1", "finding_type": "composite_narrative",
         "title": "Full attack chain summary", "source_tools": ["a"] * 8,
         "claims": []}
    is_syn, _ = is_synthesis_finding(f)
    assert is_syn is True


def test_deterministic_without_semantic_not_exempted():
    # the guard requires a registered malicious_semantic -- a deterministic
    # finding with none is not granted the atomic exemption
    f = dict(_egress_finding())
    f["malicious_semantic_signals"] = []
    is_syn, _ = is_synthesis_finding(f)
    assert is_syn is True            # falls back to the composite_narrative rule


def test_egress_finding_routes_out_of_synthesis_bucket():
    bucket, reasons = derive_final_disposition(_egress_finding())
    assert bucket != "synthesis_narrative", reasons


def test_multi_process_deterministic_still_atomic():
    # even with 3+ distinct process entities, a deterministic semantic detection
    # is atomic (the >=3-process synthesis signal must not override the guard)
    f = _egress_finding()
    f["claims"] = [{"type": "pid", "pid": 1, "process": "a.exe"},
                   {"type": "pid", "pid": 2, "process": "b.exe"},
                   {"type": "pid", "pid": 3, "process": "c.exe"}]
    is_syn, sig = is_synthesis_finding(f)
    assert is_syn is False, sig
