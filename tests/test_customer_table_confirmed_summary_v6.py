from __future__ import annotations

import json
from pathlib import Path

from sift_sentinel.reporting.customer_findings_table import render_customer_findings_table


def test_confirmed_summary_line_without_legacy_columns(tmp_path: Path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "finding_disposition_buckets.json").write_text(
        json.dumps(
            {
                "confirmed_malicious_atomic": [],
                "suspicious_needs_review": [{"id": "F054", "title": "Needs review"}],
                "inconclusive_unresolved": [{"id": "F007", "title": "Inconclusive"}],
                "benign_or_false_positive": [{"id": "F001", "title": "Benign"}],
                "synthesis_narrative": [{"id": "F053", "title": "Narrative"}],
            }
        )
    )
    text = render_customer_findings_table(state_dir=str(state))

    assert "Confirmed malicious findings: 0" in text
    assert "Severity" not in text
    assert "Confidence" not in text
    assert "State:" not in text
    assert "## Actionable / Needs Review" in text
    assert "## Self-Correction / Inconclusive" in text
    assert "## Benign / False Positive" in text


def test_confirmed_summary_uses_explicit_input_precedence():
    text = render_customer_findings_table(
        {
            "finding_disposition_buckets": {
                "confirmed_malicious_atomic": [
                    {"id": "F100", "title": "Confirmed one"},
                    {"id": "F101", "title": "Confirmed two"},
                ],
                "suspicious_needs_review": [],
                "inconclusive_unresolved": [],
                "benign_or_false_positive": [],
                "synthesis_narrative": [],
            }
        }
    )

    assert "Confirmed malicious findings: 2" in text
