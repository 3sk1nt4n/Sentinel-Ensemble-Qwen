"""C1 (Autonomous Execution Quality) surface: a visible 'the agent revised its own
conclusions' ledger -- per-finding old->new disposition + the reason, derived from
each finding's OWN self-correction / ReAct metadata. Makes real-time self-correction
legible to a judge reading the logs. Universal: reads structural metadata only,
never a case value."""
from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    render_findings_terminal,
    _self_correction_ledger,
)


def _moved(fid, src, dst, reason):
    return {
        "finding_id": fid, "description": "structural digest",
        "self_corrected": True, "_ai_finalize_from": src, "_ai_finalize_to": dst,
        "self_correction": {"applied": True, "by": "inv3a", "to": dst, "reason": reason},
    }


def _react_fp(fid, reason):
    return {
        "finding_id": fid, "description": "structural digest",
        "react_conclusion": {"verdict": "benign", "is_false_positive": True,
                             "verdict_source": "ai_react", "reasoning": reason},
    }


def _buckets():
    return {
        "confirmed_malicious_atomic": [
            _moved("F24", "suspicious_needs_review", "confirmed_malicious_atomic",
                   "validator-backed credential-tool staging")
        ],
        "suspicious_needs_review": [],
        "benign_or_false_positive": [
            _react_fp("F10", "null cmdline with zero malfind is legitimate, not injection")
        ],
        "inconclusive_unresolved": [], "synthesis_narrative": [],
    }


def test_ledger_lists_moves_with_old_new_and_reason():
    led = _self_correction_ledger(_buckets())
    assert led  # non-empty
    assert "F24" in led and "F10" in led
    # shows a transition arrow and the destination tier in words
    assert "→" in led
    assert "confirm" in led.lower() and "benign" in led.lower()
    # carries the human reason
    assert "credential-tool staging" in led
    assert "not injection" in led.lower()


def test_ledger_not_rendered_after_the_table():
    # Operator request: the SELF-CORRECTION LEDGER block is no longer printed after the
    # findings table (the self-correction signal is shown by the cyan IDs + the
    # "(N AI self-corrected)" banner count). The _self_correction_ledger() function is
    # retained and still unit-tested above; it is simply not appended to the render.
    out = render_findings_terminal(_buckets())
    assert "SELF-CORRECTION" not in out.upper()


def test_no_ledger_when_nothing_self_corrected():
    b = {
        "confirmed_malicious_atomic": [{"finding_id": "C1", "description": "lsass dump"}],
        "suspicious_needs_review": [], "benign_or_false_positive": [],
        "inconclusive_unresolved": [], "synthesis_narrative": [],
    }
    assert _self_correction_ledger(b) == ""
    assert "SELF-CORRECTION" not in render_findings_terminal(b).upper()


def test_ledger_reason_is_sanitized_of_internal_jargon():
    b = {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [
            _moved("F7", "inconclusive_unresolved", "suspicious_needs_review",
                   "srum_usage_context with score 210. Candidate cand-0061.")
        ],
        "benign_or_false_positive": [], "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }
    led = _self_correction_ledger(b)
    assert "cand-" not in led.lower()
    assert "srum_usage_context" not in led
    assert "score 210" not in led
    assert "SRUM" in led  # translated, meaning kept
