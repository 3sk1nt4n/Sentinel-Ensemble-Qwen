"""Console table: self-corrected findings get one color (cyan), ReAct-judged
findings get a nicer color (green) -- on the finding ID -- and the box stays
aligned because padding counts VISIBLE width, not ANSI codes. Universal: keys on
self_corrected / react verdict, no case data.
"""
import re
import sift_sentinel.reporting.customer_findings_table_bucket_faithful as R


def _f(fid, pid, **extra):
    d = {"finding_id": fid, "title": "t",
         "claims": [{"type": "pid", "pid": pid, "process": "p.exe"}]}
    d.update(extra)
    return d


def _render_colored():
    # force the TTY palette on for the test
    R._C, R._G, R._B, R._X = "\033[96m", "\033[92m", "\033[1m", "\033[0m"
    sc = _f("F010", 1, self_corrected=True)
    rx = _f("F036", 2, react_conclusion={"verdict": "confirmed_malicious"})
    plain = _f("F001", 3)
    buckets = {"confirmed_malicious_atomic": [rx, plain],
               "benign_or_false_positive": [sc]}
    return R.render_findings_terminal(buckets, summary={})


def test_sc_cyan_and_react_green_present():
    out = _render_colored()
    assert "\033[96m" in out   # SC -> cyan
    assert "\033[92m" in out   # ReAct -> green


def test_box_rows_stay_aligned_with_color():
    out = _render_colored()
    data_rows = [l for l in out.splitlines() if l.startswith("│")]
    visible_widths = {len(re.sub(r"\x1b\[[0-9;]*m", "", l)) for l in data_rows}
    assert len(visible_widths) == 1, visible_widths  # every row same visible width


def test_no_color_when_not_tty():
    # with empty palette (non-TTY default) the table carries no ANSI codes.
    # Blank EVERY ANSI-bearing module global, not a hand-kept list: the host
    # env may export SIFT_FORCE_COLOR=1 (import-time palette on), and any
    # palette var this test misses would leak ANSI and fail spuriously.
    saved = {}
    for name in dir(R):
        val = getattr(R, name)
        if isinstance(val, str) and "\033[" in val:
            saved[name] = val
            setattr(R, name, "")
        elif isinstance(val, dict) and any(
                isinstance(x, str) and "\033[" in x for x in val.values()):
            saved[name] = dict(val)
            setattr(R, name, {k: "" for k in val})
    try:
        sc = _f("F010", 1, self_corrected=True)
        out = R.render_findings_terminal({"benign_or_false_positive": [sc]}, summary={})
        assert "\033[" not in out
    finally:
        for name, val in saved.items():   # restore for other tests in the session
            setattr(R, name, val)
