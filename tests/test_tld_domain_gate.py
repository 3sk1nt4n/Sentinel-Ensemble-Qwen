"""Universal registrable-domain gate (D1): a token is a domain only when its
final dotted label is a registered TLD (IANA allowlist), replacing the historic,
inherently-incomplete file-extension blocklists.

ALL inputs here are SYNTHETIC / fabricated -- no case data. The point is to prove
the rule generalises by STRUCTURE: it must accept any real-TLD domain (including a
brand-new gTLD) and reject any non-TLD filename, regardless of the specific name.
A hardcoded answer-sheet would pass a real-case test but fail these fabricated
ones. Kill-switch: SIFT_DGA_TLD_GATE (exercised on the dga_score path).
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis import registrable_domain as rd  # noqa: E402
from sift_sentinel.analysis.dga_detection import dga_score  # noqa: E402


# --- the allowlist itself -----------------------------------------------------

def test_tld_set_loaded_and_nonempty():
    s = rd.tld_set()
    assert len(s) > 1000          # the real IANA set is ~1.5k
    assert rd.gate_available()


def test_real_tlds_including_new_gtlds_are_domains():
    # fabricated second-level labels on REAL TLDs -- all must be domains
    for tok in ("madeup-c2-host.com", "fictional.net", "synthetic.org",
                "example-brand.info", "totally-made-up.xyz",
                "novelthing.zip", "fabricated.mov", "invented.app"):
        assert rd.final_label_is_tld(tok), tok
        assert rd.is_registrable_domain(tok), tok


def test_filenames_and_non_tlds_are_not_domains():
    # fabricated filenames whose final segment is NOT a TLD -> never a domain
    for tok in ("somefile.sqm", "config.jrs", "fontpack.ttc", "catalog.clb",
                "helpfile.chm", "driverthing.hkf", "module.mfl",
                "data.yax", "thing.zzgibberish", "no-dot-here", ""):
        assert not rd.final_label_is_tld(tok), tok
        assert not rd.is_registrable_domain(tok), tok


def test_known_tld_single_label():
    assert rd.is_known_tld("com")
    assert rd.is_known_tld(".NET")           # case/dot tolerant
    assert not rd.is_known_tld("sqm")
    assert not rd.is_known_tld("jrs")


# --- the dga_score integration (the user-visible IOC table) -------------------

def _random_label():
    # a long, vowel-poor, high-entropy SYNTHETIC label (DGA-shaped) -- fabricated
    return "kq7zxvbnmlrtphg"


def test_dga_score_gates_filenames_out():
    # a DGA-shaped string with a FILENAME extension must NOT score (it is a file)
    suspect, score, reasons = dga_score(_random_label() + ".sqm")
    assert suspect is False
    assert score == 0.0


def test_dga_score_still_flags_real_tld_dga_domain():
    # the SAME DGA-shaped label on a REAL TLD must still flag
    suspect, score, reasons = dga_score(_random_label() + ".com")
    assert suspect is True
    assert "low_vowel_ratio" in reasons


def test_dga_tld_gate_kill_switch_restores_legacy(monkeypatch):
    # with the gate OFF, the legacy file-extension blocklist path runs; a
    # DGA-shaped .com still flags (legacy never blocked real TLDs)
    monkeypatch.setenv("SIFT_DGA_TLD_GATE", "0")
    suspect, _, _ = dga_score(_random_label() + ".com")
    assert suspect is True


def test_ordinary_brandable_domain_not_flagged():
    # a normal, vowel-rich domain on a real TLD must NOT be DGA (no false positive)
    suspect, _, _ = dga_score("printerservice.com")
    assert suspect is False
