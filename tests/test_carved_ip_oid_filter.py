"""#3a: the carve-only 'Other public IPs' list must not show OID/version
fragments. A live run listed 1.3.36.102, 1.7.3.2, 1.3.33.17 -- these are ASN.1
OID arcs (1.3.x = ISO) / version numbers carved from certs, not external hosts.
Real carved IPs (23.x, 142.250.x, 161.x) stay.

Universal: a carve-ONLY IPv4 whose first octet is <= 2 is overwhelmingly an
OID/version fragment; a genuinely contacted host in those ranges surfaces as a
LIVE socket (this filter touches only the carve-only list). Kill-switch
SIFT_CARVED_IP_OID_FILTER=0.
"""

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis import network_ioc_rollup as nr  # noqa: E402


def test_oid_shaped_carved_ips_dropped():
    for ip in ("1.3.36.102", "1.7.3.2", "1.3.33.17", "2.5.29.37", "0.9.2342.19"):
        assert nr._is_oid_or_version_carved(ip) is True, ip


def test_real_public_carved_ips_kept():
    for ip in ("23.10.138.14", "142.250.64.68", "161.69.29.157", "203.0.113.7"):
        assert nr._is_oid_or_version_carved(ip) is False, ip


def test_kill_switch(monkeypatch):
    monkeypatch.setenv("SIFT_CARVED_IP_OID_FILTER", "0")
    assert nr._is_oid_or_version_carved("1.3.36.102") is False
