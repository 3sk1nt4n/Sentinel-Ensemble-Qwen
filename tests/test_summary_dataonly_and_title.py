"""Console summary: the SIFT-SENTINEL banner title renders inside its box at the
right width even when colored. (The standalone 'data-only tools' line was removed
per operator request.) Universal: no case data.
"""
import re
from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    render_findings_terminal,
)


def _buckets():
    return {"confirmed_malicious_atomic": [
        {"finding_id": "F001", "title": "real", "source_tools": ["vol_malfind"],
         "claims": [{"type": "pid", "pid": 1, "process": "p.exe"}]}]}


def _summary():
    return {"status": "completed", "tools_count": 3,
            "tool_record_counts": {"vol_malfind": 5, "vol_handles": 100, "get_amcache": 3}}


def test_title_box_line_keeps_visible_width():
    out = render_findings_terminal(_buckets(), summary=_summary())
    title_line = next(l for l in out.splitlines() if "SIFT-SENTINEL" in l)
    visible = re.sub(r"\x1b\[[0-9;]*m", "", title_line)
    assert visible.startswith("║") and visible.rstrip().endswith("║")


def test_no_standalone_data_only_section():
    out = render_findings_terminal(_buckets(), summary=_summary())
    assert "Tools with no finding contribution (data-only)" not in out
