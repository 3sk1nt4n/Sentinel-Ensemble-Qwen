"""Network-IOC salience gate (shadow-safe). A network fact is salient only via a
structural signal (public non-vendor peer / non-baseline high-port listener /
LOLBIN owner / encoded-download URL). Universal: reuses the candidate-scoring
predicates; synthetic RFC5737 / loopback values only, no case literal."""
from sift_sentinel.analysis.network_salience import (
    network_ioc_salient,
    summarize_network_salience,
)

_PUBLIC = "8.8.8.8"          # universal public DNS -- genuinely public per ipaddress
_LOOPBACK = "127.0.0.1"      # (RFC5737 docs ranges read as private here, so not usable)


def _conn(**fields):
    return {"fact_type": "network_connection_fact", "fields": fields}


def test_public_non_vendor_peer_is_salient():
    ok, reasons = network_ioc_salient(_conn(dst_ip=_PUBLIC, owner="spinlock.exe",
                                            state="ESTABLISHED", src_port=49152))
    assert ok and "public_non_vendor_peer" in reasons


def test_loopback_ipc_is_not_salient():
    ok, reasons = network_ioc_salient(_conn(dst_ip=_LOOPBACK, owner="chrome.exe",
                                            state="ESTABLISHED", src_port=50000))
    assert ok is False and reasons == []


def test_non_baseline_high_port_listener_is_salient():
    ok, reasons = network_ioc_salient(_conn(dst_ip="", owner="rundll32.exe",
                                            state="LISTENING", src_port=49669))
    assert ok and "non_baseline_high_port_listener" in reasons


def test_baseline_service_listener_is_not_salient_by_listener_rule():
    # a sensitive baseline owner (e.g. svchost) listening high-port is not salient
    # on the listener rule alone
    ok, reasons = network_ioc_salient(_conn(dst_ip="", owner="svchost.exe",
                                            state="LISTENING", src_port=49669))
    assert "non_baseline_high_port_listener" not in reasons


def test_encoded_download_url_ioc_is_salient():
    fact = {"fact_type": "network_ioc_fact",
            "artifact": ("url", "http://example.test/a.php?cmd=base64encodeddata", "80", "public")}
    ok, reasons = network_ioc_salient(fact)
    assert ok and ("encoded_or_download_url" in reasons or "public_non_vendor_peer" in reasons)


def test_non_network_fact_is_not_salient():
    assert network_ioc_salient({"fact_type": "memory_injection_fact"}) == (False, [])


def test_summarize_counts_kept_and_dropped():
    evdb = {"typed_facts": {
        "network_connection_fact": [
            _conn(dst_ip=_PUBLIC, owner="x.exe", state="ESTABLISHED", src_port=40000),  # salient
            _conn(dst_ip=_LOOPBACK, owner="y.exe", state="ESTABLISHED", src_port=40001),  # drop
            _conn(dst_ip="10.0.0.5", owner="z.exe", state="ESTABLISHED", src_port=40002),  # drop (private)
        ],
        "memory_injection_fact": [{"fact_type": "memory_injection_fact"}],  # ignored
    }}
    s = summarize_network_salience(evdb)
    assert s["total"] == 3 and s["kept"] == 1 and s["dropped"] == 2
    assert s["by_reason"].get("public_non_vendor_peer") == 1
