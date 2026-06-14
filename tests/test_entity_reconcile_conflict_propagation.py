from sift_sentinel.analysis.entity_reconcile import find_entity_contradiction_routes


def _finding(fid, pid, process="proc.exe"):
    return {
        "finding_id": fid,
        "title": "generic finding",
        "claims": [{"type": "pid", "pid": pid, "process": process}],
    }


def _empty_buckets():
    return {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }


def test_benign_only_entity_moves_confirmed_and_medium_to_benign():
    buckets = _empty_buckets()
    buckets["confirmed_malicious_atomic"].append(_finding("C1", 100))
    buckets["suspicious_needs_review"].append(_finding("M1", 100))
    buckets["benign_or_false_positive"].append(_finding("B1", 100))

    ledger = {"pid:100": {"verdicts": ["confirmed_benign"]}}
    audit = find_entity_contradiction_routes(buckets, ledger)

    assert set(audit["move_to_benign_ids"]) == {"C1", "M1"}
    assert audit["move_to_review_ids"] == []
    assert "B1" not in audit["move_to_benign_ids"]


def test_mixed_benign_and_malicious_entity_routes_out_of_benign_and_confirmed_to_review():
    buckets = _empty_buckets()
    buckets["confirmed_malicious_atomic"].append(_finding("C2", 200))
    buckets["suspicious_needs_review"].append(_finding("M2", 200))
    buckets["benign_or_false_positive"].append(_finding("B2", 200))

    ledger = {"pid:200": {"verdicts": ["confirmed_benign", "confirmed_malicious"]}}
    audit = find_entity_contradiction_routes(buckets, ledger)

    assert set(audit["move_to_review_ids"]) == {"B2", "C2"}
    assert audit["already_review_ids"] == ["M2"]
    assert audit["move_to_benign_ids"] == []


def test_pure_malicious_entity_is_preserved():
    buckets = _empty_buckets()
    buckets["confirmed_malicious_atomic"].append(_finding("C3", 300))
    buckets["suspicious_needs_review"].append(_finding("M3", 300))

    ledger = {"pid:300": {"verdicts": ["confirmed_malicious"]}}
    audit = find_entity_contradiction_routes(buckets, ledger)

    assert audit["move_to_benign_ids"] == []
    assert audit["move_to_review_ids"] == []
    assert set(audit["pure_malicious_preserved_ids"]) == {"C3", "M3"}


def test_multi_entity_refuted_subset_routes_to_review_not_benign():
    buckets = _empty_buckets()
    buckets["confirmed_malicious_atomic"].append({
        "finding_id": "CHAIN1",
        "claims": [
            {"type": "pid", "pid": 400, "process": "one.exe"},
            {"type": "pid", "pid": 401, "process": "two.exe"},
        ],
    })

    ledger = {
        "pid:400": {"verdicts": ["confirmed_benign"]},
        "pid:401": {"verdicts": ["confirmed_malicious"]},
    }
    audit = find_entity_contradiction_routes(buckets, ledger)

    assert audit["move_to_benign_ids"] == []
    assert audit["move_to_review_ids"] == ["CHAIN1"]


def test_split_justification_preserves_finding():
    buckets = _empty_buckets()
    f = _finding("SPLIT1", 500)
    f["entity_conflict_split_justification"] = "separate evidence family"
    buckets["confirmed_malicious_atomic"].append(f)

    ledger = {"pid:500": {"verdicts": ["confirmed_benign"]}}
    audit = find_entity_contradiction_routes(buckets, ledger)

    assert audit["move_to_benign_ids"] == []
    assert audit["move_to_review_ids"] == []
    assert audit["skipped_split_justified_ids"] == ["SPLIT1"]
