"""D2: an indicator alone is NOT an IOC -- it becomes one when BOUND to a
finding. correlate_iocs_to_findings joins each surviving network indicator to
the finding(s) that reference it and INHERITS the verdict from the strongest
related finding's disposition bucket:

    confirmed_malicious_atomic  -> "confirmed"   (block/hunt list)
    suspicious_needs_review     -> "suspect"
    no related finding          -> "external"    (informational)

Join identity (adversarially adjusted): PID identity AND public-IPv4 octet
identity from the finding's OWN claims -- NEVER process-name (many-to-one on
every Windows box; would false-merge a benign socket onto a malicious finding).
Universal: claim structure + bucket names; no IOC list. Synthetic data only.
Kill-switch SIFT_IOC_CORRELATE=0.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.network_ioc_rollup import (  # noqa: E402
    build_network_ioc_section,
    correlate_iocs_to_findings,
)

_CONF = "confirmed_malicious_atomic"
_REV = "suspicious_needs_review"


def _conn(ip, port="443", proc="fakeproc.exe"):
    return {"ip": ip, "port": port, "process": proc, "direction": "outbound"}


def _finding(fid, ip=None, pid=None):
    claims = []
    if pid is not None:
        claims.append({"type": "pid", "pid": pid, "process": "fakeproc.exe"})
    if ip is not None:
        claims.append({"type": "connection", "pid": pid or 1, "dst_ip": ip})
    return {"finding_id": fid, "claims": claims, "source_tools": ["vol_netscan"]}


_IOCS = {"observed_connections": [_conn("203.0.113.77"), _conn("198.51.100.9"),
                                  _conn("192.0.2.55", proc="other.exe")],
         "suspicious_domains": [], "carved_public_ips": []}

_BUCKETS = {
    _CONF: [_finding("C001", ip="203.0.113.77", pid=4242)],
    _REV: [_finding("R001", ip="198.51.100.9", pid=777)],
}


def test_confirmed_finding_ip_inherits_confirmed():
    rows = correlate_iocs_to_findings(_IOCS, _BUCKETS)
    by_ip = {r["indicator"]: r for r in rows}
    assert by_ip["203.0.113.77"]["verdict"] == "confirmed"
    assert "C001" in by_ip["203.0.113.77"]["finding_ids"]


def test_review_finding_ip_inherits_suspect():
    rows = correlate_iocs_to_findings(_IOCS, _BUCKETS)
    by_ip = {r["indicator"]: r for r in rows}
    assert by_ip["198.51.100.9"]["verdict"] == "suspect"
    assert "R001" in by_ip["198.51.100.9"]["finding_ids"]


def test_unmatched_live_socket_is_external():
    rows = correlate_iocs_to_findings(_IOCS, _BUCKETS)
    by_ip = {r["indicator"]: r for r in rows}
    assert by_ip["192.0.2.55"]["verdict"] == "external"
    assert by_ip["192.0.2.55"]["finding_ids"] == []


def test_process_name_alone_never_joins():
    # a finding citing the SAME process name but a DIFFERENT ip must not bind
    buckets = {_CONF: [_finding("C002", ip="203.0.113.77", pid=4242)]}
    iocs = {"observed_connections": [_conn("198.51.100.250", proc="fakeproc.exe")],
            "suspicious_domains": [], "carved_public_ips": []}
    rows = correlate_iocs_to_findings(iocs, buckets)
    assert rows[0]["verdict"] == "external"
    assert rows[0]["finding_ids"] == []


def test_kill_switch(monkeypatch):
    monkeypatch.setenv("SIFT_IOC_CORRELATE", "0")
    assert correlate_iocs_to_findings(_IOCS, _BUCKETS) == []


def test_section_renders_verdict_tiers():
    db = {"typed_facts": {"network_connection_fact": [
        {"dst_ip": "203.0.113.77", "dst_port": "443", "owner": "fakeproc.exe",
         "direction": "outbound"},
        {"dst_ip": "192.0.2.55", "dst_port": "443", "owner": "other.exe",
         "direction": "outbound"},
    ]}}
    md = build_network_ioc_section(db, buckets=_BUCKETS)
    assert "Confirmed-malicious" in md
    assert "203.0.113.77" in md
    assert "C001" in md                       # the related finding is cited
    # the unmatched socket is informational, NOT in the confirmed tier
    conf_tier = md.split("Confirmed-malicious", 1)[1].split("**", 2)[0]
    assert "192.0.2.55" not in conf_tier


def test_external_tier_collapses_to_count_line():
    # FINDINGS-ONLY rendering (default): an endpoint with NO related finding is
    # observability, not an IOC -- it renders as one count line, never a table.
    db = {"typed_facts": {"network_connection_fact": [
        {"dst_ip": "192.0.2.55", "dst_port": "443", "owner": "other.exe",
         "direction": "outbound"}]}}
    md = build_network_ioc_section(db, buckets={_CONF: []})
    assert "| 192.0.2.55" not in md            # no table row for unmatched
    assert "1 external endpoint" in md         # honest count survives
    assert "Confirmed-malicious" not in md     # empty tier not rendered


def test_findings_only_kill_switch_restores_full_table(monkeypatch):
    monkeypatch.setenv("SIFT_IOC_FINDINGS_ONLY", "0")
    db = {"typed_facts": {"network_connection_fact": [
        {"dst_ip": "192.0.2.55", "dst_port": "443", "owner": "other.exe",
         "direction": "outbound"}]}}
    md = build_network_ioc_section(db, buckets={_CONF: []})
    assert "| 192.0.2.55" in md                # legacy full external table


def test_confirmed_rows_always_render_fully():
    db = {"typed_facts": {"network_connection_fact": [
        {"dst_ip": "203.0.113.77", "dst_port": "443", "owner": "fakeproc.exe",
         "direction": "outbound"}]}}
    md = build_network_ioc_section(db, buckets=_BUCKETS)
    assert "| 203.0.113.77" in md and "C001" in md


def test_section_without_buckets_is_legacy():
    db = {"typed_facts": {"network_connection_fact": [
        {"dst_ip": "203.0.113.77", "dst_port": "443", "owner": "fakeproc.exe",
         "direction": "outbound"}]}}
    md = build_network_ioc_section(db)
    assert "Confirmed-malicious" not in md    # legacy shape preserved
    assert "203.0.113.77" in md
