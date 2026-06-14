"""Slot 31G-E2a -- synthetic-ID unit tests (no real IDs/PIDs/names)."""
from sift_sentinel.analysis.entity_reconcile import (
    build_reconciliation_audit, CONFIRMED, REVIEW, BENIGN)

def _conf(entity, ids):
    return {"entity_key": entity, "conflict_type": "direct_entity_verdict_conflict",
            "conflicting_verdicts": [{"verdict": "benign", "source_finding_ids": ids},
                                     {"verdict": "malicious", "source_finding_ids": ids}]}

def _F(spec):  # {fid: (conf, n_tools, n_vrefs)}
    return [{"finding_id": k, "confidence_level": c,
             "source_tools": list(range(t)), "validator_fact_refs": list(range(v))}
            for k, (c, t, v) in spec.items()]

def test_confirmed_on_contradicted_entity_demoted():
    a = build_reconciliation_audit(
        {CONFIRMED: [{"finding_id": "S1"}], BENIGN: [{"finding_id": "S2"}]},
        [_conf("process:1", ["S1", "S2"])], _F({"S1": ("MEDIUM", 4, 1), "S2": ("LOW", 2, 1)}))
    assert a["would_move_finding_ids"] == ["S1"] and a["recommended_moves"] == 1
    assert a["per_entity"][0]["no_promotion"] is True
    assert a["per_entity"][0]["recommended_target_bucket"] == REVIEW

def test_benign_never_promoted_even_if_stronger():
    a = build_reconciliation_audit(
        {CONFIRMED: [{"finding_id": "S1"}], BENIGN: [{"finding_id": "S2"}]},
        [_conf("process:1", ["S1", "S2"])], _F({"S1": ("LOW", 1, 1), "S2": ("HIGH", 9, 9)}))
    assert a["would_move_finding_ids"] == ["S1"] and "S2" not in a["would_move_finding_ids"]

def test_noncontradicted_entity_untouched():
    a = build_reconciliation_audit({CONFIRMED: [{"finding_id": "S9"}]}, [], _F({"S9": ("HIGH", 3, 3)}))
    assert a["would_move_finding_ids"] == [] and a["conflicted_entity_count"] == 0

def test_downgrade_only_subset_of_confirmed():
    a = build_reconciliation_audit(
        {CONFIRMED: [{"finding_id": "S1"}, {"finding_id": "S3"}], BENIGN: [{"finding_id": "S2"}]},
        [_conf("process:1", ["S1", "S2"])], _F({"S1": ("MEDIUM", 2, 1), "S2": ("LOW", 2, 1), "S3": ("HIGH", 2, 1)}))
    assert set(a["would_move_finding_ids"]) <= {"S1", "S3"} and "S3" not in a["would_move_finding_ids"]

def test_strength_recorded_but_flagged_unused():
    a = build_reconciliation_audit(
        {CONFIRMED: [{"finding_id": "S1"}], BENIGN: [{"finding_id": "S2"}]},
        [_conf("process:1", ["S1", "S2"])], _F({"S1": ("MEDIUM", 4, 2), "S2": ("LOW", 1, 1)}))
    e = a["per_entity"][0]
    assert e["strength_not_used_reason"] == "evidence_quantity_not_truth_direction"
    assert "confirmed_strength_observed" in e and "benign_strength_observed" in e

def test_id_preservation():
    a = build_reconciliation_audit(
        {CONFIRMED: [{"finding_id": "S1"}], BENIGN: [{"finding_id": "S2"}], REVIEW: [{"finding_id": "S4"}]},
        [_conf("process:1", ["S1", "S2", "S4"])], _F({"S1": ("MEDIUM", 1, 1), "S2": ("LOW", 1, 1), "S4": ("MEDIUM", 1, 1)}))
    e = a["per_entity"][0]
    seen = set(e["current_confirmed_finding_ids"]) | set(e["current_benign_finding_ids"]) | set(e["current_review_finding_ids"])
    assert {"S1", "S2", "S4"} <= seen


def test_malicious_vs_inconclusive_is_not_routed():
    c = {"entity_key": "process:1", "conflict_type": "direct_entity_verdict_conflict",
         "conflicting_verdicts": [{"verdict": "inconclusive", "source_finding_ids": ["S1"]},
                                  {"verdict": "malicious", "source_finding_ids": ["S1"]}]}
    a = build_reconciliation_audit({CONFIRMED: [{"finding_id": "S1"}]}, [c], _F({"S1": ("HIGH", 3, 1)}))
    assert a["would_move_finding_ids"] == []
    assert a["uncertainty_conflicts_skipped"] == 1
    assert a["conflicted_entity_count"] == 0

def test_malicious_vs_benign_still_routed():
    c = {"entity_key": "process:1", "conflict_type": "direct_entity_verdict_conflict",
         "conflicting_verdicts": [{"verdict": "benign", "source_finding_ids": ["S1", "S2"]},
                                  {"verdict": "malicious", "source_finding_ids": ["S1", "S2"]}]}
    a = build_reconciliation_audit({CONFIRMED: [{"finding_id": "S1"}], BENIGN: [{"finding_id": "S2"}]},
                                   [c], _F({"S1": ("MEDIUM", 2, 1), "S2": ("LOW", 1, 1)}))
    assert a["would_move_finding_ids"] == ["S1"]
    assert a["uncertainty_conflicts_skipped"] == 0


def test_gates_clean_run_all_pass():
    from sift_sentinel.analysis.entity_reconcile import evaluate_reconciliation_gates
    audit = {"would_move_finding_ids": [], "confirmed_at_risk_count": 0,
             "raw_conflict_count": 0, "confirmed_before": 3, "confirmed_after": 3}
    g = dict((n, s) for n, s, _ in evaluate_reconciliation_gates(
        audit, {CONFIRMED: [{"finding_id": "A"}]}))
    assert all(v == "PASS" for v in g.values())

def test_gates_downgrade_only_and_no_confirmed():
    from sift_sentinel.analysis.entity_reconcile import evaluate_reconciliation_gates
    audit = {"would_move_finding_ids": ["X"], "confirmed_at_risk_count": 1,
             "raw_conflict_count": 1, "confirmed_before": 3, "confirmed_after": 2}
    # X correctly removed from confirmed -> all pass
    g = dict((n, s) for n, s, _ in evaluate_reconciliation_gates(
        audit, {CONFIRMED: [{"finding_id": "Y"}]}))
    assert g["NO_CONFLICTED_ENTITY_CONFIRMED_GATE"] == "PASS"
    assert g["ENTITY_RECONCILIATION_DOWNGRADE_ONLY_GATE"] == "PASS"
    # X still confirmed + count went up -> two FAILs
    bad = {"would_move_finding_ids": ["X"], "confirmed_at_risk_count": 1,
           "raw_conflict_count": 1, "confirmed_before": 2, "confirmed_after": 3}
    gb = dict((n, s) for n, s, _ in evaluate_reconciliation_gates(
        bad, {CONFIRMED: [{"finding_id": "X"}]}))
    assert gb["NO_CONFLICTED_ENTITY_CONFIRMED_GATE"] == "FAIL"
    assert gb["ENTITY_RECONCILIATION_DOWNGRADE_ONLY_GATE"] == "FAIL"

def test_gates_route_not_vacuous():
    from sift_sentinel.analysis.entity_reconcile import evaluate_reconciliation_gates
    # at_risk>0 but nothing moved -> ROUTE fails (no vacuous pass)
    audit = {"would_move_finding_ids": [], "confirmed_at_risk_count": 1,
             "raw_conflict_count": 1, "confirmed_before": 2, "confirmed_after": 2}
    g = dict((n, s) for n, s, _ in evaluate_reconciliation_gates(audit, {CONFIRMED: []}))
    assert g["ENTITY_RECONCILIATION_ROUTE_GATE"] == "FAIL"


def test_benign_only_demotes_calibration_confirm():
    from sift_sentinel.analysis.entity_reconcile import find_benign_only_demotions
    led = {"process:10": {"verdicts": ["benign"]}}
    bk = {CONFIRMED: [{"finding_id": "F101", "claims": [{"type": "pid", "pid": 10}]}]}
    assert find_benign_only_demotions(bk, led)["moved_finding_ids"] == ["F101"]

def test_benign_only_skips_mixed_entity():
    from sift_sentinel.analysis.entity_reconcile import find_benign_only_demotions
    led = {"process:10": {"verdicts": ["benign", "malicious"]}}
    bk = {CONFIRMED: [{"finding_id": "F101", "claims": [{"type": "pid", "pid": 10}]}]}
    assert find_benign_only_demotions(bk, led)["moved_finding_ids"] == []

def test_benign_only_skips_finding_touching_malicious():
    from sift_sentinel.analysis.entity_reconcile import find_benign_only_demotions
    led = {"process:10": {"verdicts": ["benign"]}, "process:20": {"verdicts": ["malicious"]}}
    bk = {CONFIRMED: [{"finding_id": "F101",
                       "claims": [{"type": "pid", "pid": 10}, {"type": "pid", "pid": 20}]}]}
    assert find_benign_only_demotions(bk, led)["moved_finding_ids"] == []

def test_synthesis_dependency_flags_citation_of_moved():
    from sift_sentinel.analysis.entity_reconcile import find_synthesis_dependency_demotions
    bk = {"synthesis_narrative": [
        {"finding_id": "F201", "_user_synth_signals": ["owns 1 malicious PID(s) [F009]"]},
        {"finding_id": "F202", "_user_synth_signals": ["owns 1 malicious PID(s) [F050]"]}]}
    assert find_synthesis_dependency_demotions(bk, ["F009"])["moved_finding_ids"] == ["F201"]

def test_synthesis_dependency_noop_without_moves():
    from sift_sentinel.analysis.entity_reconcile import find_synthesis_dependency_demotions
    bk = {"synthesis_narrative": [{"finding_id": "F201", "_user_synth_signals": ["[F009]"]}]}
    assert find_synthesis_dependency_demotions(bk, [])["moved_finding_ids"] == []
