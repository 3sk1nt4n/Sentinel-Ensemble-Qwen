"""D1-final (universal, supersedes the collision-set list): a domain is a DGA
NETWORK IOC only when it has positive network provenance -- it was seen as the
host of a parsed URL (or in a connection). A bare carved string that merely
LOOKS domain-shaped but appeared in no network context is not a network
indicator, regardless of its TLD.

This is the same principle as D2 (an indicator alone is not an IOC) and it
removes EVERY filename flood without enumerating extensions -- the trap that
.cab (a real gTLD on version-dotted Windows Update files) and .ax (the Aland
ccTLD on DirectShow filter files) slipped through. Real DGA C2 carries a beacon
URL / connection, so recall is preserved. Synthetic facts only.
Kill-switch SIFT_DGA_REQUIRE_PROVENANCE=0.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.network_ioc_rollup import extract_network_iocs  # noqa: E402

_RAND = "kqxzvbnmlrtph"          # synthetic DGA-shaped stem


def _ioc(kind, value):
    # network_ioc_fact artifact = [type, value, port_or_None, classification]
    return {"artifact": [kind, value, None, "unknown"]}


def _db(facts):
    return {"typed_facts": {"network_ioc_fact": facts}}


def test_carved_only_dga_domain_dropped():
    # a DGA-shaped real-TLD token seen ONLY as a carved string -> not listed
    db = _db([_ioc("domain", _RAND + ".ax"),
              _ioc("domain", "windows6.1-kbxxxxxxx-x64.cab")])
    out = extract_network_iocs(db)
    names = {d["domain"] for d in out["suspicious_domains"]}
    assert names == set(), names


def test_url_host_dga_domain_still_listed():
    # the SAME DGA shape, but seen as a URL host -> kept (real network IOC)
    db = _db([_ioc("url", "http://" + _RAND + ".com/beacon"),
              _ioc("domain", _RAND + ".com")])
    out = extract_network_iocs(db)
    names = {d["domain"] for d in out["suspicious_domains"]}
    assert (_RAND + ".com") in names


def test_kill_switch_restores_carved_scoring(monkeypatch):
    monkeypatch.setenv("SIFT_DGA_REQUIRE_PROVENANCE", "0")
    db = _db([_ioc("domain", _RAND + ".com")])
    out = extract_network_iocs(db)
    names = {d["domain"] for d in out["suspicious_domains"]}
    assert (_RAND + ".com") in names        # legacy: carved DGA scored
