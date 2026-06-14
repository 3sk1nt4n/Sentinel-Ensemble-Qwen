"""Tests for report_validation.py -- Pipeline Step 14 citation + schema checks."""

import pytest

from sift_sentinel.validation.report_validation import validate_report


# ── Helpers ──────────────────────────────────────────────────────────────

def _finding(fid="F-001", artifact="payload.exe", tool_call_ids=None,
             raw_excerpt="line 47: payload.exe|SHA1:a3f2|14:22:07",
             source_tools=None, confidence_level="HIGH", **extra):
    """Build a minimal valid finding dict."""
    f = {
        "finding_id": fid,
        "artifact": artifact,
        "tool_call_ids": tool_call_ids or ["tc-001"],
        "raw_excerpt": raw_excerpt,
        "source_tools": source_tools or ["vol_pstree"],
        "confidence_level": confidence_level,
    }
    f.update(extra)
    return f


def _report(narrative="", findings=None):
    """Build a minimal report dict."""
    r = {"report": narrative}
    if findings is not None:
        r["findings"] = findings
    return r


# ── Citation check ───────────────────────────────────────────────────────

class TestCitationCheck:
    """Safety net 1: every F-XXX in narrative must exist in validated findings."""

    def test_valid_report_all_citations_match(self):
        findings = [_finding("F-001"), _finding("F-002")]
        report = _report(
            "Investigation found F-001 (payload.exe) and F-002 confirming lateral movement.",
            findings=[_finding("F-001"), _finding("F-002")],
        )
        result = validate_report(report, findings)
        assert result["valid"] is True
        assert result["errors"] == []

    def test_report_citing_nonexistent_finding_id(self):
        findings = [_finding("F-001")]
        report = _report(
            "As seen in F-001 and F-999, the attacker moved laterally.",
        )
        result = validate_report(report, findings)
        assert result["valid"] is False
        assert any("F-999" in e for e in result["errors"])

    def test_multiple_invalid_citations(self):
        findings = [_finding("F-001")]
        report = _report("Evidence from F-002 and F-003 shows compromise.")
        result = validate_report(report, findings)
        assert result["valid"] is False
        assert any("F-002" in e for e in result["errors"])
        assert any("F-003" in e for e in result["errors"])

    def test_no_citations_in_narrative(self):
        """Narrative with no F-XXX references is valid (no citations to check)."""
        findings = [_finding("F-001")]
        report = _report("The system was compromised via FTP.")
        result = validate_report(report, findings)
        assert result["valid"] is True

    def test_citation_in_code_block(self):
        """F-XXX inside narrative still checked."""
        findings = [_finding("F-001")]
        report = _report("See finding F-001 and also F-777.")
        result = validate_report(report, findings)
        assert result["valid"] is False
        assert any("F-777" in e for e in result["errors"])


# ── Schema enforcement ───────────────────────────────────────────────────

class TestSchemaEnforcement:
    """Safety net 3: every finding in report must have required fields."""

    def test_finding_missing_finding_id(self):
        bad = {"artifact": "test.exe", "tool_call_ids": ["tc-001"],
               "raw_excerpt": "line 1: test"}
        findings = [_finding("F-001")]
        report = _report("Report text.", findings=[bad])
        result = validate_report(report, findings)
        assert result["valid"] is False
        assert any("finding_id" in e for e in result["errors"])

    def test_finding_missing_tool_call_ids(self):
        bad = {"finding_id": "F-001", "artifact": "test.exe",
               "raw_excerpt": "line 1: test"}
        findings = [_finding("F-001")]
        report = _report("See F-001.", findings=[bad])
        result = validate_report(report, findings)
        assert result["valid"] is False
        assert any("tool_call_ids" in e for e in result["errors"])

    def test_finding_missing_raw_excerpt(self):
        bad = {"finding_id": "F-001", "artifact": "test.exe",
               "tool_call_ids": ["tc-001"]}
        findings = [_finding("F-001")]
        report = _report("See F-001.", findings=[bad])
        result = validate_report(report, findings)
        assert result["valid"] is False
        assert any("raw_excerpt" in e for e in result["errors"])

    def test_finding_empty_tool_call_ids(self):
        bad = {"finding_id": "F-001", "artifact": "test.exe",
               "tool_call_ids": [], "raw_excerpt": "line 1: test"}
        findings = [_finding("F-001")]
        report = _report("See F-001.", findings=[bad])
        result = validate_report(report, findings)
        assert result["valid"] is False
        assert any("tool_call_ids" in e for e in result["errors"])

    def test_valid_findings_schema(self):
        good = _finding("F-001")
        findings = [_finding("F-001")]
        report = _report("See F-001.", findings=[good])
        result = validate_report(report, findings)
        assert result["valid"] is True
        assert not any("schema" in e.lower() for e in result["errors"])

    def test_multiple_schema_errors(self):
        bad1 = {"artifact": "a.exe", "tool_call_ids": ["tc-001"],
                "raw_excerpt": "test"}
        bad2 = {"finding_id": "F-002", "artifact": "b.exe"}
        findings = [_finding("F-001")]
        report = _report("Report.", findings=[bad1, bad2])
        result = validate_report(report, findings)
        assert result["valid"] is False
        assert len(result["errors"]) >= 2


# ── Vocabulary constraint ────────────────────────────────────────────────

class TestVocabularyConstraint:
    """Vocabulary check is WARNING only (disabled-by-default per SKILL.md)."""

    def test_vocabulary_not_in_findings_produces_warning(self):
        findings = [_finding("F-001", artifact="payload.exe",
                             raw_excerpt="line 47: payload.exe|SHA1:a3f2")]
        report = _report(
            "The ransomware encrypted all files on the system.",
        )
        result = validate_report(report, findings)
        # Vocabulary violations are warnings, not errors
        assert any("vocabulary" in w.lower() or "ransomware" in w.lower()
                    for w in result["warnings"])

    def test_vocabulary_from_findings_no_warning(self):
        findings = [_finding("F-001", artifact="payload.exe",
                             raw_excerpt="payload.exe connected to 192.0.2.42")]
        report = _report("Finding F-001: payload.exe connected to 192.0.2.42.")
        result = validate_report(report, findings)
        # No vocabulary warnings when all terms come from findings
        vocab_warnings = [w for w in result["warnings"]
                          if "vocabulary" in w.lower()]
        assert vocab_warnings == []


# ── Empty report ─────────────────────────────────────────────────────────

class TestEmptyReport:

    def test_empty_narrative(self):
        findings = [_finding("F-001")]
        report = _report("")
        result = validate_report(report, findings)
        assert result["valid"] is True
        assert any("empty" in w.lower() for w in result["warnings"])

    def test_missing_report_key(self):
        findings = [_finding("F-001")]
        result = validate_report({}, findings)
        assert result["valid"] is True
        assert any("empty" in w.lower() or "missing" in w.lower()
                    for w in result["warnings"])

    def test_empty_findings_list(self):
        report = _report("No findings to report.")
        result = validate_report(report, [])
        assert result["valid"] is True
        assert any("no validated findings" in w.lower()
                    for w in result["warnings"])


# ── Edge cases ───────────────────────────────────────────────────────────

class TestEdgeCases:

    def test_finding_id_pattern_in_hash_not_matched(self):
        """SHA1 like 'f001abc' should not be confused with finding F-001."""
        findings = [_finding("F-001")]
        report = _report("Hash f001abc was found. See F-001.")
        result = validate_report(report, findings)
        assert result["valid"] is True

    def test_report_with_findings_and_narrative(self):
        """Full report with both narrative and inline findings."""
        f1 = _finding("F-001", artifact="sqlsvc.exe")
        f2 = _finding("F-002", artifact="sample_payload.exe")
        report = _report(
            "F-001 shows sqlsvc.exe running malware. F-002 shows sample_payload.exe beacon.",
            findings=[f1, f2],
        )
        result = validate_report(report, [f1, f2])
        assert result["valid"] is True
        assert result["errors"] == []

    def test_return_shape(self):
        """Result always has valid, errors, warnings keys."""
        result = validate_report(_report("test"), [])
        assert "valid" in result
        assert "errors" in result
        assert "warnings" in result
        assert isinstance(result["valid"], bool)
        assert isinstance(result["errors"], list)
        assert isinstance(result["warnings"], list)
