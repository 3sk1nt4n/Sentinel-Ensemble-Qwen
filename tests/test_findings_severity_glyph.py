"""Each FINDINGS row carries a 1-column severity glyph (●) on its ID, colored by
the disposition TIER (red=confirmed, amber=needs-review, green=benign, grey=
inconclusive) so severity reads at a glance. The glyph is exactly one visible
column, so the box borders stay aligned (emoji would be 2 cols = unsafe).

Universal/structural: keyed only on the disposition BUCKET, never on case data."""
import re

from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    render_findings_terminal,
    _GLYPH_COLOR,
    _R, _Y, _G, _D,
)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _buckets():
    return {
        "confirmed_malicious_atomic": [
            {"finding_id": "F1", "title": "lsass credential dump",
             "source_tools": ["vol_malfind", "vol_pstree"], "claims": []}
        ],
        "suspicious_needs_review": [
            {"finding_id": "F2", "title": "admin share access",
             "source_tools": ["vol_netscan"], "claims": []}
        ],
        "benign_or_false_positive": [
            {"finding_id": "F3", "title": "benign updater", "claims": []}
        ],
        "inconclusive_unresolved": [], "synthesis_narrative": [],
    }


def test_glyph_color_map_keys_on_tier():
    # CONFIRMED -> red slot, NEEDS-REVIEW -> amber slot, BENIGN -> green slot.
    assert _GLYPH_COLOR["CONFIRMED"] == _R
    assert _GLYPH_COLOR["NEEDS-REVIEW"] == _Y
    assert _GLYPH_COLOR["BENIGN"] == _G
    assert _GLYPH_COLOR["INCONCLUSIVE"] == _D


def test_every_findings_row_has_a_severity_glyph():
    out = _ANSI.sub("", render_findings_terminal(_buckets()))
    # one glyph per rendered finding row (3 here), at minimum.
    assert out.count("●") >= 3
    # the glyph sits next to the finding IDs
    assert "● " in out


def test_table_borders_stay_aligned_with_glyph():
    out = render_findings_terminal(_buckets())
    plain = _ANSI.sub("", out)
    # every box line (rules + cell rows) must share one visible width per table.
    box_lines = [ln for ln in plain.splitlines()
                 if ln and ln[0] in "┌├└│"]
    assert box_lines
    by_width = {}
    for ln in box_lines:
        by_width.setdefault(len(ln), 0)
        by_width[len(ln)] += 1
    # the dominant width covers the vast majority -- a misaligned glyph would
    # split widths roughly in half. Allow the two tables (FINDINGS + FP) to differ
    # only if each is internally consistent: group consecutive lines.
    # Simpler invariant: within a single contiguous box block all widths are equal.
    block, blocks = [], []
    prev = None
    for ln in plain.splitlines():
        is_box = bool(ln) and ln[0] in "┌├└│"
        if is_box:
            block.append(len(ln))
        elif block:
            blocks.append(block)
            block = []
    if block:
        blocks.append(block)
    for blk in blocks:
        assert len(set(blk)) == 1, "borders misaligned within a table block: %r" % sorted(set(blk))
