"""The 'why it matters' sentence must reflect the finding's PRIMARY nature (its
title), not a corroborating signal that merely appears in the narrative
description. Regression for the nromanoff run where F016 (a network-listener
finding) and similar got the RWX/code-injection significance because their
DESCRIPTION mentioned 'memory injection detected'. Universal: OS primitives
only, keyed title-first; no case data.
"""
from sift_sentinel.reporting.finding_significance import plain_significance


def test_network_listener_with_injection_in_description_keys_on_network():
    # F016 shape: the title is a NETWORK LISTENER; the description happens to
    # mention 'memory injection' as corroboration. Significance must follow the
    # title (network), not the tangential injection mention.
    f = {
        "title": "remote-agent.exe listening on port 3260 with external network peer",
        "description": ("listening on 0.0.0.0:3260, established connection to a "
                        "remote host; memory injection detected in the process"),
    }
    sig = plain_significance(f)
    assert "writable and executable" not in sig, sig   # NOT the RWX line
    assert ("network connection" in sig or "command-and-control" in sig
            or "listener" in sig), sig


def test_real_rwx_finding_still_gets_rwx_significance():
    f = {"title": "explorer.exe with RWX memory injection at system boot",
         "description": "PAGE_EXECUTE_READWRITE VAD region detected"}
    assert "writable and executable" in plain_significance(f)


def test_staging_title_still_wins():
    f = {"title": "Suspicious executable staged in temp directory and executed",
         "description": "ran from AppData\\Local\\Temp; later injected code"}
    assert "temporary or staging folder" in plain_significance(f)


def test_service_execution_not_rwx_even_with_rwx_signal():
    # pinned behavior from test_report_detail_polish must still hold
    f = {"title": "Suspicious service binary execution from non-standard path",
         "description": "process ran as a service from C:\\windows",
         "malicious_semantic_signals": ["rwx_memory", "process_injection"]}
    sig = plain_significance(f)
    assert "writable and executable" not in sig
    assert "service" in sig.lower()


def test_title_blank_falls_back_to_full_text():
    # a terse deterministic finding with no title still gets its significance
    f = {"title": "", "description": "",
         "malicious_semantic_signals": ["srum_egress_outlier"]}
    assert "data left this machine" in plain_significance(f)
