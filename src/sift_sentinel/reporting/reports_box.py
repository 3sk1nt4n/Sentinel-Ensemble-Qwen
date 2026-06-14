"""Render the final 'REPORTS' box surfaced under the findings table.

A shiny rounded box (╭╮╰╯) with a centred title, listing the written artifact paths.
Width adapts to the longest 'label   value' so full paths are never truncated, and every
line is padded to the SAME visible width (ANSI codes excluded) so the borders stay aligned.
Colour is optional so piped / non-TTY output is plain. Dataset-agnostic: pure formatting.
"""
from __future__ import annotations

# ANSI (bright cyan border, bold, dim labels, reset)
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
# Optional per-row value highlight, keyed on a hint string in the 3rd tuple slot.
_ROW_COLORS = {"green": _GREEN, "cyan": _CYAN, "yellow": _YELLOW}

_TITLE = " REPORTS "
_GAP = "   "          # between label column and value
_PAD = 2              # inner side padding


def render_reports_box(rows, color: bool = True) -> str:
    """rows: iterable of (label, value) or (label, value, color_hint). The
    optional color_hint ('green'|'cyan'|'yellow') tints that row's VALUE so a
    key artifact (e.g. the interactive HTML report) stands out. Padding is
    computed from VISIBLE text only, so ANSI never shifts the borders."""
    norm = []
    for row in rows:
        if not row:
            continue
        _l = str(row[0])
        _v = str(row[1]) if len(row) > 1 else ""
        _c = str(row[2]).lower() if len(row) > 2 and row[2] else ""
        if _v:
            norm.append((_l, _v, _c))
    rows = norm
    if not rows:
        return ""
    label_w = max(len(l) for l, _, _ in rows)
    # plain content per row: "  <label padded><gap><value>"
    plains = ["  %-*s%s%s" % (label_w, l, _GAP, v) for l, v, _ in rows]
    inner = max(max(len(p) for p in plains), len(_TITLE) + 8) + _PAD

    cy = _CYAN if color else ""
    bd = _BOLD if color else ""
    dm = _DIM if color else ""
    rs = _RESET if color else ""

    # top border with centred title
    dash = inner - len(_TITLE)
    left = dash // 2
    right = dash - left
    top = "%s%s╭%s%s%s╮%s" % (cy, bd, "─" * left, _TITLE, "─" * right, rs)
    bottom = "%s%s╰%s╯%s" % (cy, bd, "─" * inner, rs)

    out = [top]
    for (label, value, chint), plain in zip(rows, plains):
        pad = inner - len(plain)
        # label dim; value default unless a color hint tints it. Pad by VISIBLE length.
        vcol = _ROW_COLORS.get(chint, "") if color else ""
        vend = (bd + rs) if vcol else ""   # restore after a tinted value
        body = "  %s%-*s%s%s%s%s%s" % (dm, label_w, label, rs, _GAP, vcol, value, vend)
        out.append("%s%s│%s%s%s%s%s│%s" % (
            cy, bd, rs, body, " " * max(0, pad), cy, bd, rs))
    out.append(bottom)
    # 2-space left indent to match the surrounding console output
    return "\n".join("  " + line for line in out)
