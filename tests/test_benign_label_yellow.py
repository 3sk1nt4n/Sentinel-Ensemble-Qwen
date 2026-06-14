"""'Assessed benign:' is painted yellow on a TTY (draws the eye to the WHY),
and stays plain in the .md (no ANSI when not a TTY). Universal -- label only."""

import importlib
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)


def _reload_with_color():
    os.environ["SIFT_FORCE_COLOR"] = "1"
    import sift_sentinel.reporting.customer_findings_table_bucket_faithful as t
    return importlib.reload(t)


def _reload_no_color():
    os.environ.pop("SIFT_FORCE_COLOR", None)
    import sift_sentinel.reporting.customer_findings_table_bucket_faithful as t
    return importlib.reload(t)


def test_yellow_on_tty():
    t = _reload_with_color()
    out = t._colorize_benign_prefix("Assessed benign: it was loopback only.")
    assert "\033[93m" in out and "Assessed benign:" in out


def test_plain_in_markdown():
    t = _reload_no_color()
    try:
        out = t._colorize_benign_prefix("Assessed benign: it was loopback only.")
        assert "\033[" not in out
        assert out.startswith("Assessed benign:")
    finally:
        _reload_no_color()


def test_non_benign_text_untouched():
    t = _reload_with_color()
    out = t._colorize_benign_prefix("Why it matters: something.")
    assert out == "Why it matters: something."
    _reload_no_color()
