"""A finding IN the benign bucket must always explain WHY it is benign --
never show the malicious 'Why it matters' significance text.

Live defect SHAPE: two benign-bucket rows carried none of the explainer's
finding-internal markers (no react_conclusion, no final_disposition stamp,
no disposition_reasons), so _benign_explanation returned '' and the row
fell through to the scary malicious significance sentence. Bucket
membership is the renderer's OWN ground truth -- it must outrank marker
reconstruction. Universal: keyed on bucket membership, no case data.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (  # noqa: E402
    _benign_explanation,
    _details_for_display,
    build_bucket_faithful_customer_findings_table,
)


def _markerless(fid="F005", title="RWX memory region in svchost.exe"):
    # NO react_conclusion / final_disposition / disposition_reasons markers.
    return {
        "finding_id": fid,
        "title": title,
        "evidence_type": "memory_injection",
        "source_tools": ["vol_malfind"],
        "claims": [{"type": "pid", "pid": 5, "process": "svchost.exe"}],
    }


def test_markerless_benign_bucket_row_explains_benign_not_why_it_matters():
    buckets = {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [],
        "inconclusive_unresolved": [],
        "benign_or_false_positive": [_markerless()],
        "synthesis_narrative": [],
    }
    table = build_bucket_faithful_customer_findings_table(buckets)
    benign_rows = [l for l in table.splitlines() if "F005" in l and "|" in l]
    assert benign_rows, table
    assert any("Assessed benign:" in l for l in benign_rows)
    assert all("Why it matters:" not in l for l in benign_rows)


def test_bucket_param_outranks_missing_markers():
    f = _markerless()
    assert _benign_explanation(f) == ""            # markers alone: not benign
    out = _benign_explanation(f, in_benign_bucket=True)
    assert out.startswith("Assessed benign:")
    det = _details_for_display(f, in_benign_bucket=True)
    assert "Assessed benign:" in det and "Why it matters:" not in det


def test_non_benign_sections_unaffected():
    f = _markerless(fid="F002")
    det = _details_for_display(f)                  # default: not benign bucket
    assert "Assessed benign:" not in det
    buckets = {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [_markerless(fid="F002")],
        "inconclusive_unresolved": [],
        "benign_or_false_positive": [],
        "synthesis_narrative": [],
    }
    table = build_bucket_faithful_customer_findings_table(buckets)
    rows = [l for l in table.splitlines() if "F002" in l and "|" in l]
    assert rows and all("Assessed benign:" not in l for l in rows)


def test_marker_carrying_benign_finding_keeps_react_explanation():
    f = _markerless()
    f["react_conclusion"] = {
        "is_false_positive": True,
        "text": "managed-runtime JIT allocation, image-backed, no shellcode",
    }
    out = _benign_explanation(f, in_benign_bucket=True)
    assert out.startswith("Assessed benign:")
    assert "managed-runtime JIT allocation" in out
