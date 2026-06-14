"""Egress / data-exfil findings must get a 'Why it matters' sentence.

Live acme run: F053 ('data exfiltration egress outlier') got significance
(its title contains 'exfiltrat'), but F040 ('Data egress outlier in SRUM for
Microsoft Edge') got NONE -- the vocabulary had 'exfiltrat' but not 'egress',
so the headline egress finding rendered with a bare, junior-unfriendly detail.
The significance keys on the OS/behavioural primitive (large outbound data
volume), never a case value.
"""
from sift_sentinel.reporting.finding_significance import plain_significance


def test_egress_outlier_title_gets_significance():
    s = plain_significance({"title": "Data egress outlier in SRUM for Microsoft Edge"})
    assert s, "egress finding got no significance"
    assert "data" in s.lower() and ("exfiltrat" in s.lower() or "left this machine" in s.lower())


def test_srum_egress_artifact_gets_significance():
    s = plain_significance({"title": "data exfiltration egress outlier",
                            "artifact": "srum egress 64.4 GB appid:1"})
    assert s


def test_plain_browsing_path_not_falsely_flagged():
    # a normal path finding with no egress/exfil vocab must not get the egress line
    s = plain_significance({"title": "Execution from temp staging directory"})
    assert "left this machine" not in s.lower()   # gets the staging line instead, or empty


def test_existing_connection_significance_still_works():
    # the egress entry must not shadow the existing C2/connection one.
    s = plain_significance({"title": "Outbound connection to command-and-control"})
    assert s and "network connection" in s.lower()
