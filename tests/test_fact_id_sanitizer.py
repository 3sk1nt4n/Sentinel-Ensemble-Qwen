"""Customer details must not leak internal zero-padded fact-index suffixes
("record-0000504", "process-0000131", "/-0002530"). The LEADING ZERO is the
discriminator, so dates / port ranges / VADs / versions / IPs are never touched.
Universal: structural, no case data.
"""
import re

from sift_sentinel.reporting.customer_findings_table_bucket_faithful import _sanitize_details as S


def test_strips_glued_and_bare_fact_ids():
    cases = [
        "AppCompatCache execution record-0000504",
        "a network connection-0000032, a network connection-0000047",
        "rundll32.exe execution.-0000097",
        "ImagePath entries./-0002530",
        "staging process-0000131 chain",
        "synthetic foo-0009999 bar",
    ]
    for src in cases:
        out = S(src)
        assert not re.search(r"-0\d{5,}", out), (src, out)


def test_never_touches_legit_hyphenated_numbers():
    # each of these must keep all of its digits (no over-reach)
    legit = [
        "VAD 0x14a0000-0x1478fff region",
        "decimal VAD 45678592-45686783 range",
        "date 2012-04-06 logged",
        "ports 8081-8082 listener",
        "RPC range 49152-65535 dynamic",
        "version 3.0.0.638.4 installed",
        "IP 56.251.168.26 and 10.3.16.5:48769",
        "CVE-2021-44228 style id",
        "range 49152-49183 ports",
    ]
    for src in legit:
        out = S(src)
        assert re.findall(r"\d", out) == re.findall(r"\d", src), (src, out)


def test_keeps_the_word_before_the_stripped_id():
    assert "record" in S("execution record-0000504")
    assert "connection" in S("a network connection-0000032")
    # a sentence period before a "/-NNNN" ref is preserved
    assert S("ImagePath entries./-0002530").rstrip().endswith("entries.")
