"""D3 (detail): minted fact-id RANGE/LIST idioms leak the bare second id into
customer prose. The existing sanitizer strips the dash form (``..._fact-0000011``)
but 'fact-0000008 through 0000011' / 'fact-0000005, 0000006' leave a bare
zero-padded counter behind.

UNIVERSAL + anchor-constrained (adversarial requirement): the bare-id strip fires
ONLY (a) when the original text contained a minted fact citation, and (b) on a
zero-padded 6+ digit token following a joiner (through/and/to/comma). A bare
``\\b0\\d{5,}\\b`` stripper is FORBIDDEN -- it mangles SIDs/USNs/offsets (their
digit groups are hyphen-flanked or hex, never joiner-led). Synthetic inputs only.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (  # noqa: E402
    _sanitize_details,
)


def test_range_idiom_bare_id_stripped():
    s = _sanitize_details(
        "supported by widget_fact-0000008 through 0000011 and a network connection.")
    assert "0000011" not in s
    assert "0000008" not in s
    assert "network connection" in s


def test_list_idiom_bare_id_stripped():
    s = _sanitize_details(
        "corroborated by thing_fact-0000005, 0000006. More prose follows.")
    assert "0000006" not in s
    assert "More prose follows" in s


def test_sid_never_mangled():
    sid = "S-1-5-21-3623811015-3361044348-0030300820-1013"
    s = _sanitize_details("Token owner %s confirmed by gadget_fact-0000001." % sid)
    assert sid in s                     # SID survives byte-identical
    assert "0000001" not in s


def test_no_fact_citation_means_no_strip():
    # without a minted fact citation in the text, zero-padded tokens are DATA
    s = _sanitize_details("Registry value 0000123 and serial 0456789 observed.")
    assert "0000123" in s
    assert "0456789" in s
