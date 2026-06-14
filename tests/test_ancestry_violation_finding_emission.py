from sift_sentinel.analysis.ancestry_findings import (
    audit_ancestry_violation_coverage,
    build_ancestry_violation_findings,
)
from sift_sentinel.analysis.malicious_semantics import has_malicious_semantic
from sift_sentinel.validation.ancestry import KNOWN_PARENTS, check_ancestry
from sift_sentinel.validation.validator import _check_child_process


def _sample_invariant_names():
    # Uses the existing OS-invariant table dynamically rather than dataset names.
    child, expected = next(
        (name, parents) for name, parents in KNOWN_PARENTS.items() if parents
    )
    return child, expected[0]


def test_ancestry_violation_emits_validator_backed_finding():
    child_name, _expected_parent = _sample_invariant_names()
    rows = [
        {"PID": 100, "PPID": 1, "ImageFileName": "unexpected-parent.exe"},
        {"PID": 200, "PPID": 100, "ImageFileName": child_name},
    ]
    violations = check_ancestry(rows)

    findings = build_ancestry_violation_findings(violations, [])
    assert len(findings) == 1

    finding = findings[0]
    assert finding["deterministic_kind"] == "process_ancestry_violation"
    assert finding["source_tools"] == ["vol_pstree"]
    assert finding["severity"] == "HIGH"

    child_claims = [
        c for c in finding["claims"] if c.get("type") == "child_process"
    ]
    assert child_claims == [
        {"type": "child_process", "parent_pid": 100, "child_pid": 200}
    ]

    ref = {
        "pid_to_process": {
            100: "unexpected-parent.exe",
            200: child_name,
        },
        "pid_to_parent_pid": {200: 100},
    }
    result = _check_child_process(child_claims[0], ref)
    assert "MATCH" in str(result).upper()


def test_expected_parent_emits_no_finding():
    child_name, expected_parent = _sample_invariant_names()
    rows = [
        {"PID": 100, "PPID": 1, "ImageFileName": expected_parent},
        {"PID": 200, "PPID": 100, "ImageFileName": child_name},
    ]
    violations = check_ancestry(rows)
    assert violations == []
    assert build_ancestry_violation_findings(violations, []) == []


def test_existing_child_process_claim_prevents_duplicate():
    child_name, _expected_parent = _sample_invariant_names()
    rows = [
        {"PID": 100, "PPID": 1, "ImageFileName": "unexpected-parent.exe"},
        {"PID": 200, "PPID": 100, "ImageFileName": child_name},
    ]
    violations = check_ancestry(rows)
    existing = [
        {
            "finding_id": "F001",
            "claims": [
                {"type": "child_process", "parent_pid": 100, "child_pid": 200}
            ],
        }
    ]

    assert build_ancestry_violation_findings(violations, existing) == []
    audit = audit_ancestry_violation_coverage(violations, existing)
    assert audit["gate"] == "PASS"
    assert audit["covered_count"] == 1


def test_missing_ancestry_coverage_fails_closed():
    child_name, _expected_parent = _sample_invariant_names()
    rows = [
        {"PID": 100, "PPID": 1, "ImageFileName": "unexpected-parent.exe"},
        {"PID": 200, "PPID": 100, "ImageFileName": child_name},
    ]
    violations = check_ancestry(rows)
    audit = audit_ancestry_violation_coverage(violations, [])
    assert audit["gate"] == "FAIL"
    assert audit["missing_count"] == 1


def test_ancestry_finding_has_malicious_semantic_signal():
    child_name, _expected_parent = _sample_invariant_names()
    rows = [
        {"PID": 100, "PPID": 1, "ImageFileName": "unexpected-parent.exe"},
        {"PID": 200, "PPID": 100, "ImageFileName": child_name},
    ]
    violations = check_ancestry(rows)
    finding = build_ancestry_violation_findings(violations, [])[0]

    has_semantic, signals = has_malicious_semantic(finding, None)
    assert has_semantic is True
    assert "process_ancestry_violation" in signals
