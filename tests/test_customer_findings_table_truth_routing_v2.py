from sift_sentinel.reporting.customer_findings_table import render_customer_findings_table


def _buckets():
    return {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [
            {
                "id": "F001",
                "title": "Generic actionable suspicious observation",
                "claims": [
                    {
                        "type": "pid",
                        "pid": 100,
                        "process": "generic.exe",
                        "status": "MATCH",
                        "source_tool": "vol_pstree",
                    }
                ],
                "source_tools": ["vol_pstree"],
            },
            {
                "id": "F002",
                "title": "Summary: Generic multi-source synthesis",
                "type": "synthesis_narrative",
                "claims": [
                    {
                        "type": "pid",
                        "pid": 200,
                        "process": "summary.exe",
                        "status": "MATCH",
                        "source_tool": "vol_pstree",
                    }
                ],
                "source_tools": ["vol_pstree"],
            },
            {
                "id": "F003",
                "title": "Generic ReAct-refuted observation",
                "react_verdict": "confirmed_benign",
                "claims": [
                    {
                        "type": "pid",
                        "pid": 300,
                        "process": "benign.exe",
                        "status": "MATCH",
                        "source_tool": "vol_cmdline",
                    }
                ],
                "source_tools": ["vol_cmdline"],
            },
        ],
        "inconclusive_unresolved": [
            {
                "id": "F004",
                "title": "Generic unsupported hypothesis",
                "self_correction_status": "dropped_honest",
                "claims": [],
            }
        ],
        "benign_or_false_positive": [
            {
                "id": "F005",
                "title": "Generic benign false-positive finding",
                "claims": [
                    {
                        "type": "pid",
                        "pid": 500,
                        "process": "known-good.exe",
                        "status": "MATCH",
                        "source_tool": "vol_psscan",
                    }
                ],
                "source_tools": ["vol_psscan"],
            }
        ],
    }


def _section(text, name):
    start = text.index(f"## {name}")
    rest = text[start + len(f"## {name}") :]
    next_pos = rest.find("\n## ")
    if next_pos >= 0:
        return rest[:next_pos]
    return rest


def test_truth_routing_does_not_show_severity_confidence():
    text = render_customer_findings_table({"finding_disposition_buckets": _buckets()})
    assert "Severity" not in text
    assert "Confidence" not in text


def test_synthesis_not_actionable_when_no_confirmed_atomic():
    text = render_customer_findings_table({"finding_disposition_buckets": _buckets()})
    actionable = _section(text, "Actionable / Needs Review")
    narrative = _section(text, "Narrative / Context")
    assert "F001" in actionable
    assert "F002" not in actionable
    assert "F002" in narrative


def test_react_benign_forced_to_bottom_fp_section():
    text = render_customer_findings_table({"finding_disposition_buckets": _buckets()})
    actionable = _section(text, "Actionable / Needs Review")
    fp = _section(text, "Benign / False Positive")
    assert "F003" not in actionable
    assert "F003" in fp
    assert text.index("## Benign / False Positive") > text.index("## Self-Correction / Inconclusive")


def test_sc_stays_in_sc_section():
    text = render_customer_findings_table({"finding_disposition_buckets": _buckets()})
    sc = _section(text, "Self-Correction / Inconclusive")
    fp = _section(text, "Benign / False Positive")
    assert "F004" in sc
    assert "F004" not in fp


def test_dedup_prefers_fp_truth_over_actionable():
    buckets = _buckets()
    buckets["benign_or_false_positive"].append(
        {
            "id": "F001",
            "title": "Same finding later classified benign",
            "react_verdict": "confirmed_benign",
            "claims": [],
        }
    )
    text = render_customer_findings_table({"finding_disposition_buckets": buckets})
    actionable = _section(text, "Actionable / Needs Review")
    fp = _section(text, "Benign / False Positive")
    assert "F001" not in actionable
    assert "F001" in fp
