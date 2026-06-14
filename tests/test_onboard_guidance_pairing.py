"""The onboarding guidance leads with the ideal (a memory+disk PAIR works best,
cross-domain corroboration) before reassuring that single-source is fine and the
card explains what the evidence can and can't find. Universal UI, no case data."""
from sift_sentinel.onboard.presenter import guidance


def test_guidance_leads_with_pair_works_best():
    g = guidance(color=False).lower()
    assert "works best" in g
    assert "memory" in g and "disk" in g
    assert "corroborate" in g or "cross-domain" in g      # the WHY a pair is best
    assert "strongest" in g


def test_guidance_still_reassures_single_source():
    g = guidance(color=False).lower()
    assert "memory-only or disk-only is fine" in g
    assert "can and can't find" in g
    assert "one folder = one case" in g


def test_guidance_plain_is_ansi_free():
    assert "\x1b[" not in guidance(color=False)
