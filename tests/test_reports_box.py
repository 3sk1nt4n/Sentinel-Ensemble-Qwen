"""The final 'REPORTS' box that surfaces the written artifact paths under the findings
table. A shiny rounded box with a centered title; borders must stay aligned regardless of
path length, and colour must be omittable for non-TTY / piped output.
"""
import re

from sift_sentinel.reporting.reports_box import render_reports_box

ROWS = [
    ("Forensic report", "/home/x/reports/incident_report_20260609.md"),
    ("Live session", "/home/x/reports/live_session_20260609_154216.txt"),
]

_ANSI = re.compile(r"\033\[[0-9;]*m")


def _visible(line):
    return _ANSI.sub("", line)


def test_box_has_title_and_all_values():
    out = render_reports_box(ROWS, color=False)
    assert "REPORTS" in out
    for _label, val in ROWS:
        assert val in out
    for label, _val in ROWS:
        assert label in out


def test_borders_are_aligned_same_visible_width():
    out = render_reports_box(ROWS, color=False)
    lines = [ln for ln in out.splitlines() if ln.strip()]
    widths = {len(_visible(ln)) for ln in lines}
    assert len(widths) == 1, "box lines are not the same visible width: %s" % widths
    # rounded corners present
    assert lines[0].lstrip().startswith("╭")  # ╭
    assert lines[-1].lstrip().startswith("╰")  # ╰


def test_color_false_has_no_ansi():
    out = render_reports_box(ROWS, color=False)
    assert "\033[" not in out


def test_color_true_has_ansi_but_same_visible_width():
    out = render_reports_box(ROWS, color=True)
    assert "\033[" in out
    lines = [ln for ln in out.splitlines() if ln.strip()]
    widths = {len(_visible(ln)) for ln in lines}
    assert len(widths) == 1


def test_single_row_still_balanced():
    out = render_reports_box([("Forensic report", "/tmp/r.md")], color=False)
    lines = [ln for ln in out.splitlines() if ln.strip()]
    assert len({len(_visible(ln)) for ln in lines}) == 1
    assert "REPORTS" in out


def test_long_path_does_not_break_alignment():
    long = "/opt/cases/reports/" + "x" * 80 + ".md"
    out = render_reports_box([("Forensic report", long)], color=False)
    lines = [ln for ln in out.splitlines() if ln.strip()]
    assert len({len(_visible(ln)) for ln in lines}) == 1
    assert long in out
