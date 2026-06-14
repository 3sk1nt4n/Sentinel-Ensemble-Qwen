"""Confirmed-bucket corroboration discipline (alice inversion fix).

A finding may enter confirmed_malicious_atomic ONLY when its malicious meaning is
corroborated by an INDEPENDENT axis -- a non-weak/non-history semantic signal, an
external (public) network connection, two distinct injection-capable memory
tools, or a conclusive structural primitive. Two universal corrections:

  * PROMOTE: an RWX-injection finding that ALSO beacons to an external public IP
    (e.g. lsass.exe -> a public C2) is corroborated -> eligible. (Was demoted by
    rwx_uncorroborated.)
  * DEMOTE: a finding whose ONLY malicious signal is weak-alone / disk-history
    (e.g. executes_from_temp_path -- an installer staged in Temp) with no
    independent corroborator is NOT confirm-eligible, even via inv3a. (Was
    over-confirmed because inv3a's confirm path skipped the weak-alone floor.)

Universal: keyed on signal class + public-IP octet shape + injection-tool set --
no case data; relabel any IP/process and the verdict is unchanged. Kill-switch
SIFT_CONFIRM_CORROBORATION_FLOOR=0.
"""
from sift_sentinel.analysis.disposition import (
    _confirmable_corroborator_present,
    _has_external_network_corroborator,
    rwx_uncorroborated_for_finding,
    weak_alone_only_uncorroborated,
    _RWX_SIGNAL,
)

_RWX = _RWX_SIGNAL
_TEMP = "executes_from_temp_path"


def _f(**kw):
    base = {"finding_id": "F", "title": "t", "claims": [], "source_tools": []}
    base.update(kw)
    return base


# ── external public-IP corroborator ──────────────────────────────────────
def test_public_ip_in_connection_claim_is_corroborator():
    f = _f(source_tools=["vol_netscan"],
           claims=[{"type": "connection", "foreign_addr": "198.51.100.26"}])
    assert _has_external_network_corroborator(f) is True


def test_public_ip_in_finding_text_with_netscan_is_corroborator():
    f = _f(source_tools=["vol_netscan"],
           description="lsass.exe maintaining connections to 198.51.100.26")
    assert _has_external_network_corroborator(f) is True


def test_private_ip_is_not_an_external_corroborator():
    for ip in ("10.3.58.4", "192.168.1.5", "172.16.5.1", "127.0.0.1"):
        f = _f(source_tools=["vol_netscan"],
               claims=[{"type": "connection", "foreign_addr": ip}])
        assert _has_external_network_corroborator(f) is False, ip


def test_public_ip_without_network_context_is_not_corroborator():
    # a public-looking number in an unrelated field, no connection/netscan
    f = _f(description="version 198.51.100.26 string", source_tools=["get_amcache"])
    assert _has_external_network_corroborator(f) is False


# ── RWX promote: injection + external C2 ─────────────────────────────────
def test_rwx_with_external_c2_is_corroborated():
    f = _f(source_tools=["vol_malfind", "vol_netscan"],
           claims=[{"type": "connection", "foreign_addr": "203.0.113.27"}])
    assert rwx_uncorroborated_for_finding(f, True, [_RWX]) is False


def test_rwx_alone_still_uncorroborated():
    f = _f(source_tools=["vol_malfind"])
    assert rwx_uncorroborated_for_finding(f, True, [_RWX]) is True


def test_rwx_with_two_injection_tools_is_corroborated():
    f = _f(source_tools=["vol_malfind", "vol_ldrmodules"])
    assert _confirmable_corroborator_present(f, [_RWX]) is True


# ── weak-alone floor: staging-only installer ─────────────────────────────
def test_temp_staging_alone_is_not_confirmable():
    f = _f(source_tools=["run_appcompatcacheparser", "extract_mft_timeline"])
    assert weak_alone_only_uncorroborated(f, [_TEMP]) is True


def test_temp_staging_with_external_c2_is_confirmable():
    f = _f(source_tools=["vol_netscan"],
           claims=[{"type": "connection", "foreign_addr": "203.0.113.9"}])
    assert weak_alone_only_uncorroborated(f, [_TEMP]) is False


def test_strong_non_weak_signal_is_confirmable():
    # a real behavioural/structural signal alongside is corroboration
    f = _f()
    assert weak_alone_only_uncorroborated(
        f, [_TEMP, "anti_forensics_execution"]) is False


def test_no_malicious_signal_is_not_floored():
    # the floor only applies when there IS a weak-alone signal; empty -> other
    # gates handle it, this floor returns False (not its job)
    assert weak_alone_only_uncorroborated(_f(), []) is False


def test_kill_switch_disables_floor(monkeypatch):
    monkeypatch.setenv("SIFT_CONFIRM_CORROBORATION_FLOOR", "0")
    f = _f(source_tools=["run_appcompatcacheparser"])
    assert weak_alone_only_uncorroborated(f, [_TEMP]) is False
