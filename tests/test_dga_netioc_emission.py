"""Bare-domain network-IOC findings: a DGA-shaped host carried by a
network_ioc_fact (no URL wrapper, no IP) must (a) not be confused with a carved
FILENAME (gara.ttf / 21d13ed0.msi), and (b) actually become a scored candidate
so a real DGA / algorithmic C2 domain surfaces as a finding. Universal: keyed on
host STRING STRUCTURE + a universal file-format extension set -- never a domain
or malware name; relabel the host and the verdict is unchanged.
"""
from sift_sentinel.analysis.malicious_semantics import (
    _netioc_host_value,
    match_dga_domain,
    _view,
)


def _netfact(host):
    return {"fact_type": "network_ioc_fact", "artifact": ["domain", host],
            "value": host}


# ── filename guard: carved filenames are NOT domains ─────────────────────
def test_filename_with_format_extension_is_not_a_host():
    # Non-TLD file-format extensions are filtered out as carved filenames.
    for fname in ("gara.ttf", "arialnb.ttf", "pwrpnt12.pptx",
                  "21d13ed0.msi", "sendtoonenotenames.gpd", "outlook.dll",
                  "report.pdf", "image.png"):
        flat, _b, _f = _view(_netfact(fname))
        assert _netioc_host_value(flat) == "", fname


def test_tld_colliding_extension_survives_but_non_dga_emits_nothing():
    # .zip/.com are also real TLDs, so the host is NOT filtered -- but the DGA
    # gate means an ordinary token like archive.zip still emits no candidate.
    from sift_sentinel.analysis.candidate_observations import _score_fact
    _s, sig, _u = _score_fact(_netfact("archive.zip"))
    assert "dga_domain" not in sig


def test_hex_filename_does_not_false_positive_as_dga():
    # 21d13ed0 is digit/consonant-heavy -> would score DGA>=2 if treated as host
    assert match_dga_domain(_netfact("21d13ed0.msi")) is False


def test_real_domain_still_resolves_as_host():
    flat, _b, _f = _view(_netfact("login.example.com"))
    assert _netioc_host_value(flat) == "login.example.com"


# ── DGA structural detection on a bare domain ────────────────────────────
def test_dga_shaped_bare_domain_matches():
    # long, high-entropy, consonant/digit-heavy registrable label
    assert match_dga_domain(_netfact("kq3v9xzr7mwp2bf.com")) is True


def test_ordinary_domain_is_not_dga():
    assert match_dga_domain(_netfact("mail.google.com")) is False


# ── candidate emission: a DGA bare domain becomes a scored candidate ─────
def test_dga_bare_domain_emits_candidate_signal():
    from sift_sentinel.analysis.candidate_observations import _score_fact
    fact = _netfact("kq3v9xzr7mwp2bf.com")
    score, signals, suppressions = _score_fact(fact)
    assert "dga_domain" in signals, (score, signals)
    assert score >= 70, score


def test_ordinary_bare_domain_emits_no_dga_candidate():
    from sift_sentinel.analysis.candidate_observations import _score_fact
    fact = _netfact("mail.google.com")
    score, signals, suppressions = _score_fact(fact)
    assert "dga_domain" not in signals


def test_filename_emits_no_candidate():
    from sift_sentinel.analysis.candidate_observations import _score_fact
    score, signals, suppressions = _score_fact(_netfact("21d13ed0.msi"))
    assert "dga_domain" not in signals
