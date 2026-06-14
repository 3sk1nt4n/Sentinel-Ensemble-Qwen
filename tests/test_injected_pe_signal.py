"""Confirm-gate fix (#1 / C2): an RWX region whose CONTENT is an injected PE /
shellcode emits a DISTINCT semantic signal that corroborates the bare RWX signal,
so a real injected PE (e.g. spinlock.exe) is no longer treated as 'RWX alone' and
can reach confirmed. A benign JIT RWX region (no payload) is unaffected. Universal:
keyed on the payload characterization token, no case value."""
from sift_sentinel.analysis.malicious_semantics import (
    match_injected_pe_image_in_executable_memory as _m,
    MALICIOUS_SEMANTIC_SIGNALS,
)
from sift_sentinel.analysis.disposition import _rwx_uncorroborated


def test_signal_is_registered():
    assert "injected_pe_image_in_executable_memory" in MALICIOUS_SEMANTIC_SIGNALS
    entry = MALICIOUS_SEMANTIC_SIGNALS["injected_pe_image_in_executable_memory"]
    assert entry["required_fact_types"] == ["memory_injection_fact"]


def test_matcher_fires_on_injected_pe_or_shellcode():
    assert _m({"fact_type": "memory_injection_fact", "characterization": "mz_pe"}) is True
    assert _m({"fact_type": "memory_injection_fact", "characterization": "shellcode"}) is True
    assert _m({"fact_type": "memory_injection_fact", "payload": "PE_header detected"}) is True


def test_matcher_does_not_fire_on_bare_rwx_or_wrong_type():
    # bare RWX region with no payload characterization (a JIT region looks like this)
    assert _m({"fact_type": "memory_injection_fact",
               "protection": "PAGE_EXECUTE_READWRITE"}) is False
    # right payload token but wrong fact type
    assert _m({"fact_type": "network_connection_fact", "characterization": "mz_pe"}) is False


def test_injected_pe_corroborates_rwx_gate():
    # RWX alone -> uncorroborated (blocked from confirmed)
    assert _rwx_uncorroborated(True, ["rwx_memory_region_with_unusual_protection"]) is True
    # RWX + injected PE payload -> corroborated (eligible for confirmed)
    assert _rwx_uncorroborated(
        True,
        ["rwx_memory_region_with_unusual_protection",
         "injected_pe_image_in_executable_memory"],
    ) is False
