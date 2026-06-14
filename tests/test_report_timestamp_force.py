"""Defect C: the report carries TWO date strings -- the header 'Report Date:' and the
footer 'Report Generated:'. Both must be forced to a full UTC timestamp (date AND
time); the Inv4 LLM routinely writes a date-only value. Universal: structural label
match only, never a case value. The timestamp is caller-supplied so this is testable.
"""
from sift_sentinel.reporting.report_polish import force_report_timestamps

TS = "2026-06-09 06:54:51"


def test_report_date_header_forced_to_full_timestamp():
    out = force_report_timestamps("**Report Date:** 2026-06-09 (UTC)", TS)
    assert out == "**Report Date:** 2026-06-09 06:54:51 (UTC)"


def test_report_generated_footer_forced():
    out = force_report_timestamps("> **Report Generated:** 2026-06-09 (UTC)", TS)
    assert out == "> **Report Generated:** 2026-06-09 06:54:51 (UTC)"


def test_both_in_one_document_both_forced():
    md = ("**Report Date:** 2026-06-09 (UTC)\n\nbody body body\n\n"
          "> **Report Generated:** 2026-06-09 (UTC)\n")
    out = force_report_timestamps(md, TS)
    assert out.count("06:54:51") == 2


def test_already_full_timestamp_is_renormalised_idempotently():
    md = "**Report Date:** 2026-06-09 06:54:51 (UTC)"
    assert force_report_timestamps(md, TS) == md


def test_non_label_dates_untouched():
    md = "The incident occurred on 2026-09-16 (UTC) per SRUM."
    assert force_report_timestamps(md, TS) == md
