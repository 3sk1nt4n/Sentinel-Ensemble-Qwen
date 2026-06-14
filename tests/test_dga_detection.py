"""DGA (Domain Generation Algorithm) detection -- universal structure, no domain list.
Random-looking C2 labels flag; real brandable/short domains do not. Synthetic domains
only (invented), so the swap-test holds on any held-out box.
"""
from sift_sentinel.analysis.dga_detection import dga_score, flag_dga_domains


def test_random_low_vowel_label_flags_as_dga():
    for d in ("kqzxvbnmlprst.com", "x7sf2kq9zlp.net", "qwrtpzxcvbnm.org"):
        is_sus, score, reasons = dga_score(d)
        assert is_sus, (d, score, reasons)
        assert "low_vowel_ratio" in reasons


def test_real_brandable_and_short_domains_do_not_flag():
    # normal vowel ratios / too short to classify -> never flagged (FP-safe)
    for d in ("microsoftonline.com", "exampleservice.org", "google.com",
              "newsletter.example.com", "cdn.shopfront.net"):
        is_sus, score, reasons = dga_score(d)
        assert not is_sus, (d, score, reasons)


def test_scores_the_registrable_sld_not_structured_subdomains():
    # DGA in the registrable SLD is caught...
    assert dga_score("kq7zxvbnmlphd.com")[0]
    # ...but a structured legit infra subdomain over a normal SLD is NOT flagged
    # (we score the SLD 'verisign', not the 'csc3-2010-crl' subdomain).
    assert not dga_score("csc3-2010-crl.verisign.com")[0]


def test_carving_fragments_are_rejected():
    # bulk_extractor UTF-16 carve noise (single chars joined by dashes) is not a domain
    for frag in ("u-l-c-6-e-p-a-a-0-z-m-s-m-00.example.com",
                 "8-4-f-p-t-6-4-8.net"):
        assert not dga_score(frag)[0]


def test_flag_dga_domains_ranks_and_counts_and_preserves_freq():
    domains = [
        {"value": "kqzxvbnmlprst.com", "count": 40},
        {"value": "microsoftonline.com", "count": 900},
        {"value": "x7sf2kq9zlp.net", "count": 5},
    ]
    suspects, n = flag_dga_domains(domains, max_items=10)
    flagged = {s["domain"] for s in suspects}
    assert flagged == {"kqzxvbnmlprst.com", "x7sf2kq9zlp.net"}   # benign excluded
    assert n == 2
    assert suspects[0]["count"] in (40, 5)                       # histogram freq preserved
    assert flag_dga_domains([], 5) == ([], 0)
