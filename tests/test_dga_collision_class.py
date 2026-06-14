"""D1-residual: extensions that are ALSO real IANA TLDs (.zip/.sh/.so/.py/...)
cannot be separated from domains by the TLD set alone -- a random-stem carved
FILENAME like ``kqxzvbnmlp.zip`` still DGA-scored (proven leak). The
discriminator is PROVENANCE: for the bounded TLD∧file-extension collision set,
a 2-label token is DGA-scorable only when it arrived from a URL/host context
(it was the host of a parsed URL) or has >=3 labels (an explicit subdomain).
Everything outside the collision set keeps pure TLD-gate behavior.

Also: carved dotted-quads must be CANONICAL -- a leading-zero octet
(09.16.16.45) is carve junk, never a host; additive to the existing first-octet
OID filter. All inputs synthetic. Kill-switches SIFT_DGA_PROVENANCE_GATE /
SIFT_CARVED_IP_CANON_FILTER.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.dga_detection import dga_score  # noqa: E402
from sift_sentinel.analysis.network_ioc_rollup import _is_noncanonical_quad  # noqa: E402

_RAND = "kq7zxvbnmlrtphg"          # synthetic DGA-shaped stem


def test_collision_ext_carved_does_not_score():
    # a random-stem .zip/.sh/.py token WITHOUT url provenance is a carved file
    for ext in ("zip", "sh", "so", "py", "rs", "pl"):
        assert dga_score(_RAND + "." + ext, provenance="carved")[0] is False, ext
        assert dga_score(_RAND + "." + ext)[0] is False, ext   # unknown = carved


def test_collision_ext_url_host_still_scores():
    # the SAME token seen as the HOST of a real URL is a domain -> must flag
    assert dga_score(_RAND + ".zip", provenance="url_host")[0] is True


def test_collision_ext_three_labels_scores():
    # an explicit subdomain is domain-shaped even without URL provenance
    assert dga_score("c2." + _RAND + ".zip", provenance="carved")[0] is True


def test_non_collision_tld_unaffected_by_provenance():
    # outside the collision set the TLD gate alone decides (no recall loss)
    assert dga_score(_RAND + ".com", provenance="carved")[0] is True
    assert dga_score(_RAND + ".sqm", provenance="url_host")[0] is False  # not a TLD


def test_provenance_gate_kill_switch(monkeypatch):
    monkeypatch.setenv("SIFT_DGA_PROVENANCE_GATE", "0")
    assert dga_score(_RAND + ".zip", provenance="carved")[0] is True  # legacy


def test_noncanonical_quad_rejected():
    assert _is_noncanonical_quad("09.16.16.45") is True     # leading zero
    assert _is_noncanonical_quad("203.0.113.300") is True   # octet > 255
    assert _is_noncanonical_quad("203.0.113.45") is False   # canonical survives


def test_noncanonical_kill_switch(monkeypatch):
    monkeypatch.setenv("SIFT_CARVED_IP_CANON_FILTER", "0")
    assert _is_noncanonical_quad("09.16.16.45") is False
