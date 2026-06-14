"""Slot 31E-DB.3 -- final disposition truth bucket tests.

Dataset-agnostic. No API key, no live run, no network. All fixtures are
synthetic; the real-state replay test reads the latest local
/tmp/sift-sentinel-run-* state dir read-only and skips when absent.
"""

from __future__ import annotations

import glob
import json
import os

import pytest

from sift_sentinel.analysis.disposition import (
    BUCKET_BENIGN,
    BUCKET_CONFIRMED,
    BUCKET_INCONCLUSIVE,
    BUCKET_SUSPICIOUS,
    BUCKET_SYNTHESIS,
    REQUIRED_BUCKETS,
    assert_buckets_partition_findings,
    derive_final_disposition,
    extract_react_verdict,
    has_strong_typed_support,
    is_synthesis_finding,
    route_findings_for_report,
    validate_disposition_buckets,
)


def _atomic(**kw):
    """A finding that clears every gate unless overridden.

    Slot 31E-DB.5: the confirmed bucket also requires source
    attribution, a raw excerpt, and a malicious semantic signal.

    Slot 31E-DB.5a-alpha: the confirmed bucket additionally requires
    (TASK 1) durable validator-attached fact references, (TASK 2)
    semantic-signal provenance, and (TASK 3) at least one behavioural
    malicious claim beyond PID/process existence. The "clears every
    gate" baseline grows those fields; assertions are unchanged, only
    the gate-clearing surface grew (same pattern as Slot 31E-DB.5).
    `validator_metadata` is deliberately NOT set here so the
    has_strong_typed_support no-metadata contract still holds.
    """
    base = {
        "finding_id": "F001",
        "title": "synthetic atomic finding",
        "finding_type": "atomic",
        "evidence_type": "disk",
        "severity": "HIGH",
        "confidence_level": "HIGH",
        "validation_status": "MATCH",
        "deterministic_check": "passed",
        "self_verification_passed": True,
        "source_tools": ["vol_pstree"],
        "tool_call_ids": ["tc-atomic-001"],
        "raw_excerpt": "synthetic excerpt clearing the evidence gate",
        "malicious_semantic_signals": [
            "rwx_memory_region_with_unusual_protection"
        ],
        # TASK 2: provenance for the declared semantic signal.
        "semantic_signal_support": [
            {
                "signal": "rwx_memory_region_with_unusual_protection",
                "supporting_fact_type": "memory_injection_fact",
                "supporting_tool": "vol_malfind",
                "supporting_fact_refs": ["memory_injection_fact:synthetic"],
                "supporting_raw_excerpt": (
                    "private PAGE_EXECUTE_READWRITE region, no backing file"
                ),
            }
        ],
        # TASK 1: durable validator-attached fact references.
        "validator_fact_refs": [
            {"fact_type": "process_fact", "claim_type": "pid",
             "source": "typed_evidence_db"},
        ],
        # TASK 3: a behavioural claim (hash) beyond PID identity.
        "claims": [
            {"type": "pid", "pid": 1000, "process": "a.exe"},
            {"type": "hash", "sha1": "ab", "filename": "a.exe"},
        ],
    }
    base.update(kw)
    return base


# ── extract_react_verdict ────────────────────────────────────────────────

def test_explicit_react_verdict_beats_freetext_fallback():
    f = _atomic(
        react_verdict="confirmed_malicious",
        conclusion="this is inconclusive insufficient evidence",
    )
    verdict, meta = extract_react_verdict(f, None)
    assert verdict == "confirmed_malicious"
    assert meta["source"] == "finding.react_verdict"


def test_does_not_scan_full_serialized_finding():
    # "benign" appears only as generic prose in a non-conclusion field.
    f = _atomic(
        artifact="process looks benign at first glance but is malware",
        description="initially benign-seeming staging behavior",
    )
    verdict, meta = extract_react_verdict(f, None)
    assert verdict is None
    assert meta["source"] == "none"


def test_freetext_fallback_scans_conclusion_only():
    f = _atomic(conclusion="After review this is a confirmed_benign result")
    verdict, meta = extract_react_verdict(f, None)
    assert verdict == "confirmed_benign"
    assert meta["source"] == "conclusion_text"


def test_react_conclusion_runtime_shape_extracted():
    f = _atomic(react_conclusion={"verdict": "confirmed_benign",
                                   "is_false_positive": True})
    verdict, meta = extract_react_verdict(f, None)
    assert verdict == "confirmed_benign"
    assert meta["source"] == "finding.react_conclusion"


def test_react_conclusion_regex_fallback_fp_becomes_likely_fp():
    f = _atomic(react_conclusion={"verdict": "inconclusive",
                                   "is_false_positive": True,
                                   "verdict_source": "regex_fallback"})
    verdict, _ = extract_react_verdict(f, None)
    assert verdict == "likely_fp"


def test_investigations_dict_lookup():
    f = _atomic(finding_id="F042")
    invs = {"F042": {"verdict": "inconclusive"}}
    verdict, meta = extract_react_verdict(f, invs)
    assert verdict == "inconclusive"
    assert meta["source"] == "investigations[finding_id]"


def test_investigations_list_lookup():
    f = _atomic(finding_id="F042")
    invs = [{"finding_id": "F001"}, {"finding_id": "F042",
                                     "verdict": "confirmed_malicious"}]
    verdict, meta = extract_react_verdict(f, invs)
    assert verdict == "confirmed_malicious"
    assert meta["source"] == "investigations[list]"


# ── routing overrides ────────────────────────────────────────────────────

def test_confirmed_benign_routes_to_benign_bucket():
    f = _atomic(react_verdict="confirmed_benign")
    bucket, _ = derive_final_disposition(f)
    assert bucket == BUCKET_BENIGN


def test_likely_fp_routes_to_benign_bucket():
    f = _atomic(react_verdict="likely_fp")
    bucket, _ = derive_final_disposition(f)
    assert bucket == BUCKET_BENIGN


def test_inconclusive_routes_to_inconclusive_bucket():
    f = _atomic(react_verdict="inconclusive")
    bucket, _ = derive_final_disposition(f)
    assert bucket == BUCKET_INCONCLUSIVE


# ── confidence / severity truth gate ─────────────────────────────────────

def test_critical_plus_low_confidence_out_of_confirmed():
    f = _atomic(severity="CRITICAL", confidence_level="LOW")
    bucket, _ = derive_final_disposition(f)
    assert bucket != BUCKET_CONFIRMED
    assert bucket == BUCKET_SUSPICIOUS


def test_high_plus_low_confidence_out_of_confirmed():
    f = _atomic(severity="HIGH", confidence_level="LOW")
    bucket, _ = derive_final_disposition(f)
    assert bucket != BUCKET_CONFIRMED
    assert bucket == BUCKET_SUSPICIOUS


# ── synthesis routing ────────────────────────────────────────────────────

def test_strong_synthesis_finding_type_routes_to_synthesis():
    f = _atomic(finding_type="attack_chain_summary")
    is_syn, signals = is_synthesis_finding(f)
    assert is_syn and any(s.startswith("strong:") for s in signals)
    bucket, _ = derive_final_disposition(f)
    assert bucket == BUCKET_SYNTHESIS


def test_composite_narrative_runtime_label_routes_to_synthesis():
    f = _atomic(finding_type="composite_narrative")
    bucket, _ = derive_final_disposition(f)
    assert bucket == BUCKET_SYNTHESIS


def test_single_arrow_process_chain_is_not_synthesis():
    # Slot 31E-DB.5a-alpha: a single-arrow process context is still not
    # synthesis AND can still confirm -- but TASK 3 requires a
    # behavioural claim beyond PID identity, so the fixture carries an
    # explicit execution-path claim alongside the two PID claims. Two
    # distinct process entities keeps is_synthesis False (needs >= 3).
    f = _atomic(
        artifact="WmiPrvSE.exe -> powershell.exe spawned a child",
        claims=[{"type": "pid", "pid": 1000, "process": "powershell.exe"},
                {"type": "pid", "pid": 1001, "process": "wmiprvse.exe"},
                {"type": "path",
                 "path": "\\windows\\temp\\stager.exe"}],
    )
    is_syn, _ = is_synthesis_finding(f)
    assert is_syn is False
    bucket, _ = derive_final_disposition(f)
    assert bucket == BUCKET_CONFIRMED


def test_two_weak_synthesis_signals_route_to_synthesis():
    # weak: title prefix + 3 distinct PIDs
    f = _atomic(
        finding_id="Fsyn",
        title="Full attack chain across the host",
        claims=[
            {"type": "pid", "pid": 10, "process": "a.exe"},
            {"type": "child_process", "parent_pid": 10, "child_pid": 20},
            {"type": "child_process", "parent_pid": 20, "child_pid": 30},
        ],
    )
    is_syn, signals = is_synthesis_finding(f)
    assert is_syn
    assert len([s for s in signals if s.startswith("weak:")]) >= 2
    bucket, _ = derive_final_disposition(f)
    assert bucket == BUCKET_SYNTHESIS


# ── one-claim protection ─────────────────────────────────────────────────

def test_one_claim_unsupported_out_of_confirmed():
    f = _atomic(claims=[{"type": "pid", "pid": 1, "process": "x.exe"}])
    bucket, _ = derive_final_disposition(f)
    assert bucket != BUCKET_CONFIRMED
    assert bucket in (BUCKET_SUSPICIOUS, BUCKET_INCONCLUSIVE)


def test_one_claim_with_strong_typed_support_can_be_confirmed():
    # Slot 31E-DB.5a-alpha: one claim + strong independent typed support
    # can still confirm, but TASK 3 forbids a PID-only confirmed, so the
    # single claim is now a behavioural execution-path claim. The
    # one-claim-with-strong-support path is otherwise unchanged.
    f = _atomic(
        claims=[{"type": "path",
                 "path": "\\users\\public\\payload.exe"}],
        validator_metadata={
            "typed_fact_refs": [
                {"fact_type": "process_fact"},
                {"fact_type": "registry_persistence_fact"},
            ],
            "source_tools": ["vol_pstree", "parse_registry_persistence"],
        },
    )
    bucket, _ = derive_final_disposition(f)
    assert bucket == BUCKET_CONFIRMED


# ── has_strong_typed_support ─────────────────────────────────────────────

def test_strong_support_false_without_validator_metadata():
    ok, reasons = has_strong_typed_support(_atomic())
    assert ok is False
    assert reasons == ["no_validator_metadata"]


def test_strong_support_true_two_fact_families():
    f = _atomic(validator_metadata={
        "typed_fact_refs": [
            {"fact_type": "event_log_fact"},
            "registry_persistence_fact:abc",
        ],
        "source_tools": ["parse_event_logs"],
    })
    ok, reasons = has_strong_typed_support(f)
    assert ok is True
    assert any("typed_fact_types=" in r for r in reasons)


def test_strong_support_true_two_tools_with_typed_refs():
    f = _atomic(validator_metadata={
        "typed_fact_refs": ["process_fact:1"],
        "source_tools": ["vol_pstree", "vol_netscan"],
    })
    ok, reasons = has_strong_typed_support(f)
    assert ok is True
    assert any("source_tools=" in r for r in reasons)


# ── bucket validation ────────────────────────────────────────────────────

def test_route_produces_all_required_buckets():
    buckets = route_findings_for_report([_atomic()])
    for name in REQUIRED_BUCKETS:
        assert name in buckets
    assert validate_disposition_buckets(buckets) == []


def test_validate_catches_manual_bucket_corruption():
    benign = _atomic(finding_id="Fbad", react_verdict="confirmed_benign")
    buckets = {b: [] for b in REQUIRED_BUCKETS}
    # Manually corrupt: drop a benign finding into the confirmed bucket.
    benign["final_disposition"] = BUCKET_CONFIRMED
    buckets[BUCKET_CONFIRMED].append(benign)
    violations = validate_disposition_buckets(buckets)
    assert any("Fbad:benign_or_fp_in_confirmed" == v for v in violations)


def test_validate_flags_missing_bucket():
    violations = validate_disposition_buckets({BUCKET_CONFIRMED: []})
    assert any(v.startswith("missing_bucket:") for v in violations)


# ── real-state replay (read-only, skips when no local state) ─────────────

def _latest_state_dir():
    cands = sorted(
        glob.glob("/tmp/sift-sentinel-run-*"),
        key=lambda d: os.path.getmtime(d),
        reverse=True,
    )
    for d in cands:
        if os.path.isfile(os.path.join(d, "findings_final.json")):
            return d
    return None


def test_real_state_disposition_replay_no_confirmed_violations():
    sd = _latest_state_dir()
    if sd is None:
        pytest.skip("no local /tmp/sift-sentinel-run-* findings_final.json")
    with open(os.path.join(sd, "findings_final.json")) as fh:
        findings = json.load(fh)
    if not findings:
        pytest.skip("findings_final.json is empty")

    investigations = None
    itp = os.path.join(sd, "investigation_threads.json")
    if os.path.isfile(itp):
        with open(itp) as fh:
            data = json.load(fh)
        investigations = (
            data.get("investigations") if isinstance(data, dict) else data
        )

    evdb = None
    edp = os.path.join(sd, "evidence_db.json")
    if os.path.isfile(edp):
        with open(edp) as fh:
            evdb = json.load(fh)

    buckets = route_findings_for_report(
        findings, investigations=investigations, evidence_db=evdb)
    routed = sum(len(v) for v in buckets.values())
    assert routed == len(
        [f for f in findings if isinstance(f, dict)]
    ), "every finding must land in exactly one bucket"

    violations = validate_disposition_buckets(buckets)
    assert violations == [], (
        "real-state replay produced confirmed bucket violations: %s"
        % violations
    )


# ── Slot 31E-DB.4: partition assertion ──────────────────────────────────

def test_partition_clean_for_routed_buckets():
    findings = [
        _atomic(finding_id="F1"),
        _atomic(finding_id="F2", react_verdict="confirmed_benign"),
        _atomic(finding_id="F3", react_verdict="inconclusive"),
    ]
    buckets = route_findings_for_report(findings)
    assert assert_buckets_partition_findings(buckets, findings) == []


def test_partition_flags_dropped_finding():
    findings = [_atomic(finding_id="F1"), _atomic(finding_id="F2")]
    buckets = route_findings_for_report(findings)
    # Drop F2 from every bucket.
    for b in buckets.values():
        b[:] = [f for f in b if f.get("finding_id") != "F2"]
    v = assert_buckets_partition_findings(buckets, findings)
    assert any("F2:absent_from_all_buckets" == x for x in v)
    assert any(x.startswith("count_mismatch:") for x in v)


def test_partition_flags_duplicate_finding():
    findings = [_atomic(finding_id="F1")]
    buckets = route_findings_for_report(findings)
    dup = dict(buckets[BUCKET_CONFIRMED][0])
    buckets[BUCKET_BENIGN].append(dup)
    v = assert_buckets_partition_findings(buckets, findings)
    assert any("F1:in_multiple_buckets" in x for x in v)
    assert any(x.startswith("count_mismatch:") for x in v)


def test_partition_flags_unknown_bucket_name():
    findings = [_atomic(finding_id="F1")]
    buckets = route_findings_for_report(findings)
    buckets["not_a_real_bucket"] = []
    v = assert_buckets_partition_findings(buckets, findings)
    assert any("unknown_bucket:not_a_real_bucket" == x for x in v)


def test_partition_flags_orphan_injected_entry():
    findings = [_atomic(finding_id="F1")]
    buckets = route_findings_for_report(findings)
    buckets[BUCKET_INCONCLUSIVE].append(_atomic(finding_id="GHOST"))
    v = assert_buckets_partition_findings(buckets, findings)
    assert any("orphan_in_buckets:id:GHOST" in x for x in v)


def test_partition_bad_inputs():
    assert assert_buckets_partition_findings(None, []) == ["buckets_not_a_dict"]
    assert assert_buckets_partition_findings({}, None) == [
        "findings_final_not_a_list"]


# ── Slot 31E-DB.4: pinned real-state replay (Haiku run) ──────────────────

_HAIKU_STATE_DIR = os.environ.get("SIFT_HAIKU_STATE_DIR", "")
_HAIKU_KNOWN_BENIGN_IDS = (
    "F004", "F006", "F008", "F015", "F023", "F024", "F027", "F030", "F034",
)


def test_haiku_real_state_disposition_replay_pinned_counts():
    if not os.path.isdir(_HAIKU_STATE_DIR) or not os.path.isfile(
        os.path.join(_HAIKU_STATE_DIR, "findings_final.json")
    ):
        pytest.skip(
            "Haiku live-run state_dir unavailable; skipping real-state "
            "disposition replay."
        )
    with open(os.path.join(_HAIKU_STATE_DIR, "findings_final.json")) as fh:
        findings = json.load(fh)

    investigations = None
    itp = os.path.join(_HAIKU_STATE_DIR, "investigation_threads.json")
    if os.path.isfile(itp):
        with open(itp) as fh:
            data = json.load(fh)
        investigations = (
            data.get("investigations") if isinstance(data, dict) else data
        )

    evdb = None
    edp = os.path.join(_HAIKU_STATE_DIR, "evidence_db.json")
    if os.path.isfile(edp):
        with open(edp) as fh:
            evdb = json.load(fh)

    buckets = route_findings_for_report(
        findings, investigations=investigations, evidence_db=evdb)

    assert assert_buckets_partition_findings(buckets, findings) == []
    assert validate_disposition_buckets(buckets) == []

    # Slot 31E-DB.5a-alpha re-pins the post-hardening ground truth.
    # The 31E-DB.5 pin (11 confirmed) predates the TASK 1 durable
    # fact-reference gate and the TASK 2 semantic-signal provenance
    # gate. This Haiku state_dir was produced BEFORE this slot, so its
    # findings carry no validator-attached fact refs and no semantic
    # provenance blocks; the new gates therefore correctly route every
    # legacy finding OUT of confirmed_malicious_atomic (it would need a
    # re-validation pass under 5a-alpha to re-attach refs/provenance).
    # The 11 previously-confirmed move to suspicious_needs_review. This
    # is the honest measured truth, not a weakening: total still
    # partitions all 35; benign/inconclusive/synthesis unchanged;
    # known-benign ids still excluded (vacuously, confirmed is empty).
    assert len(buckets[BUCKET_CONFIRMED]) == 0
    assert len(buckets[BUCKET_BENIGN]) == 9
    assert len(buckets[BUCKET_INCONCLUSIVE]) == 7
    assert len(buckets[BUCKET_SUSPICIOUS]) == 17
    assert len(buckets[BUCKET_SYNTHESIS]) == 2

    confirmed_ids = {f.get("finding_id") for f in buckets[BUCKET_CONFIRMED]}
    for bid in _HAIKU_KNOWN_BENIGN_IDS:
        assert bid not in confirmed_ids, (
            "%s must NOT be in confirmed_malicious_atomic" % bid
        )

    total = sum(len(v) for v in buckets.values())
    assert total == len(findings) == 35
