from sift_sentinel.analysis.fp_fidelity import (
    STATUS_NOT_FP,
    STATUS_VISIBLE_FP,
    STATUS_WITHHELD,
    apply_fp_fidelity_to_buckets,
    fp_fidelity_decision,
    is_rfc1918_or_local_ipv4,
)


def _fp_finding(process="demo.exe", pid=99999, ip="203.0.113.7"):
    return {
        "finding_id": "FX001",
        "title": f"{process} connection to outside address {ip}",
        "claims": [
            {"type": "pid", "pid": pid, "process": process},
            {"type": "connection", "pid": pid, "foreign_addr": ip},
        ],
        "react_conclusion": {
            "verdict": "confirmed_benign",
            "is_false_positive": True,
            "text": "AI considered this benign",
        },
    }


def test_rfc1918_property_not_case_key():
    assert is_rfc1918_or_local_ipv4("10.0.0.7")
    assert is_rfc1918_or_local_ipv4("172.16.0.7")
    assert is_rfc1918_or_local_ipv4("192.168.1.7")
    assert not is_rfc1918_or_local_ipv4("203.0.113.7")


def test_protected_process_non_rfc1918_fp_is_withheld():
    f = _fp_finding(process="lsass.exe", ip="203.0.113.7")
    d = fp_fidelity_decision(f)
    assert d["status"] == STATUS_WITHHELD
    assert d["visible_fp"] is False
    assert "lsass.exe" in d["protected_process_names"]
    assert d["non_rfc1918_ipv4s"] == ["203.0.113.7"]


def test_same_protected_process_internal_ip_can_remain_visible_fp():
    f = _fp_finding(process="lsass.exe", ip="10.0.0.7")
    d = fp_fidelity_decision(f)
    assert d["status"] == STATUS_VISIBLE_FP
    assert d["visible_fp"] is True
    assert d["non_rfc1918_ipv4s"] == []


def test_non_protected_process_non_rfc1918_can_remain_visible_fp():
    f = _fp_finding(process="notepad.exe", ip="203.0.113.7")
    d = fp_fidelity_decision(f)
    assert d["status"] == STATUS_VISIBLE_FP
    assert d["visible_fp"] is True


def test_non_fp_candidate_is_not_visible_fp():
    f = _fp_finding(process="lsass.exe", ip="203.0.113.7")
    f["react_conclusion"] = {
        "verdict": "confirmed_malicious",
        "is_false_positive": False,
    }
    d = fp_fidelity_decision(f)
    assert d["status"] == STATUS_NOT_FP
    assert d["visible_fp"] is False


def test_apply_buckets_moves_blocked_fp_to_review_only():
    blocked = _fp_finding(process="lsass.exe", ip="203.0.113.7")
    clean = _fp_finding(process="svchost.exe", ip="10.0.0.8")
    clean["finding_id"] = "FX002"

    buckets = {
        "benign_or_false_positive": [blocked, clean],
        "suspicious_needs_review": [],
        "confirmed_malicious_atomic": [],
    }

    out, audit = apply_fp_fidelity_to_buckets(buckets)

    assert audit["gate"] == "PASS"
    assert audit["withheld_from_visible_fp_ids"] == ["FX001"]
    assert audit["visible_fp_verified_ids"] == ["FX002"]

    benign_ids = [x["finding_id"] for x in out["benign_or_false_positive"]]
    review_ids = [x["finding_id"] for x in out["suspicious_needs_review"]]

    assert "FX001" not in benign_ids
    assert "FX002" in benign_ids
    assert "FX001" in review_ids
