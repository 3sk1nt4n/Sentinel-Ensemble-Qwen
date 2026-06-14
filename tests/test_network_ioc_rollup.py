"""Network Indicators (IOC) roll-up (universal).

Grounded in the REAL compiled shapes:
  * network_connection_fact: named dst_ip/dst_port/owner/direction (+ artifact
    ``[proto, local:port, foreign:port, state, process]`` fallback).
  * network_ioc_fact.artifact = ``[type, value, port_or_None, classification]``.
No case data: public-IP octet shape + DGA structure only. RFC 5737 documentation
IPs (203.0.113/198.51.100/192.0.2) stand in for "public"; RFC1918 for "private".
"""
from sift_sentinel.analysis.network_ioc_rollup import (
    extract_network_iocs,
    build_network_ioc_section,
    insert_network_ioc_into_report,
)
from sift_sentinel.analysis.dga_detection import dga_score

# a label the universal DGA scorer flags (verified below) and a normal one
_DGA = "xkq3zw9vhn7p.net"
_NORMAL = "windowsupdate.com"


def _conn(dst_ip, dst_port, owner, direction="outbound"):
    return {"fact_type": "network_connection_fact", "dst_ip": dst_ip,
            "dst_port": dst_port, "owner": owner, "direction": direction,
            "artifact": ["TCPv4", "10.0.0.5:5555", f"{dst_ip}:{dst_port}",
                         "ESTABLISHED", owner]}


def _ioc(ioc_type, value, classification="unknown"):
    return {"fact_type": "network_ioc_fact",
            "artifact": [ioc_type, value, "None", classification]}


def _db(conns=None, iocs=None):
    return {"typed_facts": {
        "network_connection_fact": conns or [],
        "network_ioc_fact": iocs or [],
    }}


def test_dga_fixture_is_actually_flagged():
    # guard: if dga_detection thresholds change, this fixture must still be DGA
    assert dga_score(_DGA)[0] is True
    assert dga_score(_NORMAL)[0] is False


# ── extract: observed external connections ───────────────────────────────────
def test_public_connection_is_extracted_with_process():
    db = _db(conns=[_conn("203.0.113.50", 443, "evil.exe")])
    out = extract_network_iocs(db)
    assert len(out["observed_connections"]) == 1
    c = out["observed_connections"][0]
    assert c["ip"] == "203.0.113.50" and c["process"] == "evil.exe"
    assert c["port"] == "443" and c["direction"] == "outbound"


def test_private_and_loopback_connections_excluded():
    db = _db(conns=[_conn("10.3.58.5", 445, "x.exe"),
                    _conn("127.0.0.1", 80, "y.exe"),
                    _conn("192.168.1.9", 139, "z.exe")])
    assert extract_network_iocs(db)["observed_connections"] == []


def test_connections_dedup_on_ip_port_process():
    db = _db(conns=[_conn("203.0.113.50", 443, "p.exe"),
                    _conn("203.0.113.50", 443, "p.exe")])
    assert len(extract_network_iocs(db)["observed_connections"]) == 1


# ── extract: DGA domains ─────────────────────────────────────────────────────
def test_dga_domain_flagged_normal_domain_not():
    # UNIVERSAL provenance rule (supersedes carved-only scoring): the carver
    # classifies any real-TLD token as a "domain", and on a real image the vast
    # majority are filenames whose extension collides with a TLD (.cab/.ax/...).
    # A domain is DGA-listed only with network provenance -- it was seen as a URL
    # host -- so the DGA fixture must arrive via a url fact to flag.
    db = _db(iocs=[_ioc("url", "http://%s/x" % _DGA), _ioc("domain", _DGA),
                   _ioc("domain", _NORMAL)])
    out = extract_network_iocs(db)
    flagged = {d["domain"] for d in out["suspicious_domains"]}
    assert _DGA in flagged and _NORMAL not in flagged
    d = out["suspicious_domains"][0]
    assert d["score"] > 0 and "low_vowel_ratio" in d["reasons"]


def test_carved_only_dga_domain_not_listed():
    # the same DGA shape with NO url provenance (pure carve) is dropped -- this
    # is the .cab/.ax filename-flood fix, keyed on provenance not extension.
    db = _db(iocs=[_ioc("domain", _DGA)])
    out = extract_network_iocs(db)
    assert out["suspicious_domains"] == []


# ── extract: carved public IPs ───────────────────────────────────────────────
def test_carved_public_ip_listed_junk_excluded():
    db = _db(iocs=[_ioc("ipv4", "198.51.100.7", "public"),
                   _ioc("ipv4", "4.0.0.0", "public"),       # x.0 carving junk
                   _ioc("ipv4", "10.0.0.1", "private")])
    out = extract_network_iocs(db)
    assert out["carved_public_ips"] == ["198.51.100.7"]


def test_carved_ip_already_in_connection_is_deduped():
    db = _db(conns=[_conn("203.0.113.50", 443, "p.exe")],
             iocs=[_ioc("ipv4", "203.0.113.50", "public")])
    out = extract_network_iocs(db)
    assert out["carved_public_ips"] == []        # already an observed connection


# ── section ──────────────────────────────────────────────────────────────────
def test_section_renders_connections_and_dga():
    db = _db(conns=[_conn("203.0.113.50", 443, "evil.exe")],
             iocs=[_ioc("url", "http://%s/x" % _DGA), _ioc("domain", _DGA)])
    sec = build_network_ioc_section(db)
    assert sec.startswith("## Network Indicators (IOCs)")
    assert "203.0.113.50" in sec and "evil.exe" in sec
    assert _DGA in sec and "low_vowel_ratio" in sec


def test_section_says_none_when_no_dga_domains():
    db = _db(conns=[_conn("203.0.113.50", 443, "p.exe")])
    sec = build_network_ioc_section(db)
    assert "None detected" in sec               # honest: connections but no DGA


def test_section_empty_without_external_evidence():
    db = _db(conns=[_conn("10.0.0.5", 445, "x.exe")],
             iocs=[_ioc("domain", _NORMAL)])
    assert build_network_ioc_section(db) == ""


def test_insert_is_idempotent():
    db = _db(conns=[_conn("203.0.113.50", 443, "p.exe")])
    base = "# R\n\n## Key Findings\n\nx\n"
    md1, n1 = insert_network_ioc_into_report(base, db)
    assert n1 > 0 and md1.count("## Network Indicators (IOCs)") == 1
    md2, _ = insert_network_ioc_into_report(md1, db)
    assert md2.count("## Network Indicators (IOCs)") == 1


def test_insert_anchors_after_logon_section():
    db = _db(conns=[_conn("203.0.113.50", 443, "p.exe")])
    base = ("# R\n\n## Accounts & Logon Context\n\nwho\n\n## Key Findings\n\nx\n")
    md, _ = insert_network_ioc_into_report(base, db)
    assert md.index("## Accounts & Logon Context") < md.index(
        "## Network Indicators (IOCs)") < md.index("## Key Findings")


def test_kill_switch_disables(monkeypatch):
    monkeypatch.setenv("SIFT_NETWORK_IOC", "0")
    db = _db(conns=[_conn("203.0.113.50", 443, "p.exe")])
    assert build_network_ioc_section(db) == ""
    md, n = insert_network_ioc_into_report("# R\n", db)
    assert n == 0
