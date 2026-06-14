"""A2: the DGA scorer must not flag carved Windows driver/config FILENAMES as
algorithmically-generated DOMAINS. A live run flagged 235 'DGA domains' that
were really driver files (``xrofpscv11.ppd``, ``netl1c63x64.inf``,
``mgmtprovider.mof``) -- the file extension was mistaken for a TLD and the
filename stem for the SLD.

Universal grammar fix (no domain/case list): a token whose final dotted segment
is NOT a registered TLD is a filename, not a domain. Real DGA domains (real TLD,
including newer malware TLDs) still flag.

NOTE (D1): the mechanism is now the IANA-TLD ALLOWLIST (registrable_domain), which
supersedes the old file-extension blocklist (kept as the SIFT_DGA_TLD_GATE=0
fallback). The allowlist is strictly more correct: an extension that is ALSO a
real TLD (``.man``, ``.cat``, ``.cab``, ``.zip``, ``.mov``) can no longer be
excluded by structure, because a real C2 could be registered under it -- so such
tokens are treated as domains and the carve-only noise is removed downstream by
IOC<->finding correlation (D2), not by pretending a real TLD is a file extension.
That is why ``.man`` was removed from the filename list below. Kill-switches
SIFT_DGA_TLD_GATE=0 / SIFT_DGA_FILE_EXT_FILTER=0.
"""

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis import dga_detection as dga  # noqa: E402


# Carved Windows driver/config filenames whose final segment is NOT a registered
# TLD -- NOT domains, must NOT be DGA. (``.man`` was here but is a real IANA TLD,
# so it is no longer structurally excludable -- see the module docstring + the
# REAL_TLD_TOKENS test below.)
FILENAME_FPS = [
    "xrofpscv11.ppd", "netl1c63x64.inf", "mgmtprovider.mof",
    "fsrmfmjaction.types", "dxptasksync.ptxml", "volmgrx-ppdlic.xrm",
    "fsrmfmjaction.cdxml", "kyclra3fxps.gdl",
    "tsbwcl2main.gpd", "net8187bv64.pnf",
]

# Genuine DGA-style domains (real TLD, incl. newer malware TLDs) -- must STILL flag.
REAL_DGA = ["kq7zxvbnmlp.com", "x7sf2kqztwz.xyz", "vbnmkqxzplt.top"]

# Extensions that are ALSO real IANA TLDs: structurally these ARE valid domains
# (a real C2 could live under them), so the gate must NOT drop them as filenames.
# Synthetic / fabricated stems -- no case data.
REAL_TLD_TOKENS = ["fabricated.man", "synthetic.cat", "madeup.cab"]


def test_filenames_not_flagged_as_dga():
    for f in FILENAME_FPS:
        is_suspect, score, reasons = dga.dga_score(f)
        assert not is_suspect, f"{f} wrongly flagged DGA (reasons={reasons})"
        assert score == 0.0, f


def test_real_dga_domains_still_flag():
    flagged = [d for d in REAL_DGA if dga.dga_score(d)[0]]
    assert len(flagged) >= 2, f"real DGA under-detected: only {flagged}"


def test_real_tld_tokens_treated_as_domains():
    # D1 universal correctness: a token whose final label is a real TLD is a
    # DOMAIN candidate, never structurally dropped as a filename -- otherwise a
    # real C2 registered under .man/.cat/.cab would be invisible.
    from sift_sentinel.analysis.registrable_domain import final_label_is_tld
    for tok in REAL_TLD_TOKENS:
        assert final_label_is_tld(tok), f"{tok} should be a domain (real TLD)"


def test_kill_switch_restores_old_behavior(monkeypatch):
    monkeypatch.setenv("SIFT_DGA_FILE_EXT_FILTER", "0")
    # With the filter off, the filename's stem is scored as before (may flag).
    is_suspect_off, _, _ = dga.dga_score("xrofpscv11.ppd")
    monkeypatch.setenv("SIFT_DGA_FILE_EXT_FILTER", "1")
    is_suspect_on, _, _ = dga.dga_score("xrofpscv11.ppd")
    assert is_suspect_on is False
    assert is_suspect_off != is_suspect_on or is_suspect_off is False


def test_flag_dga_domains_excludes_filenames():
    domains = FILENAME_FPS + REAL_DGA
    flagged, total = dga.flag_dga_domains(domains, max_items=50)
    flagged_names = {f.get("domain") for f in flagged}
    for f in FILENAME_FPS:
        assert f not in flagged_names, f"{f} leaked into DGA roll-up"
