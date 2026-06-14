"""Regression tests for slot 31C2-FIX-A (severity ledger hardening).

Synthetic generic fixtures only. No case-specific PID, IP, user,
path, domain, or process name.

What they pin down:

  A. is_private_or_internal returns True for RFC1918 / loopback /
     link-local and False for a public address (8.8.8.8).
  B. normalize_private_ip_wording returns a 2-tuple
     (rewritten_text, deduped_first_seen_addresses_rewritten).
  C. Wording is rewritten only for private/internal addresses;
     public addresses are left exactly as-is.
  D. _NETWORK_LISTENER_TOOLS contains the real runtime tool name
     "vol_netscan" (no fake tool, no replacement).
  E. apply_post_step13_normalization rewrites title, artifact,
     description, summary, narrative, and details at minimum.
  F. A self-corrected single-tool vol_netscan synthetic finding
     gets capped at LOW and receives
     severity_ledger_route_out=True
     + severity_ledger_route_out_reason=<reason>
     + severity_ledger_cap_applied=True.
  G. Disposition routes a synthetic otherwise-eligible finding out
     of confirmed_malicious_atomic when
     severity_ledger_route_out=True.
  H. verify_no_drift flags an unauthorised LOW->CRITICAL move and
     passes when a matching allowed_reason is provided.
  I. The owned source file is literal-free of CIDR network tables
     and the 172.16.* token.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest

from sift_sentinel.analysis.severity_ledger import (
    REASON_SELF_CORRECTED_SINGLE_TOOL,
    _NETWORK_LISTENER_TOOLS,
    apply_post_step13_normalization,
    cap_self_corrected_single_tool,
    extract_ipv4,
    is_private_or_internal,
    normalize_private_ip_wording,
    record_after_step13,
    verify_no_drift,
)
from sift_sentinel.analysis.disposition import derive_final_disposition


# Synthetic generic addresses used throughout this test module.
PRIVATE_A = "10.20.30.40"        # RFC1918 10/8
PRIVATE_B = "192.168.50.10"      # RFC1918 192.168/16
LOOPBACK = "127.0.0.1"
LINKLOCAL = "169.254.1.1"
PUBLIC_ADDR = "8.8.8.8"

# Synthetic generic process / PIDs.
EXAMPLE_PID_A = 4242
EXAMPLE_PID_B = 5151
EXAMPLE_PROC = "example_service.exe"


# ────────────────────────────────────────────────────────────────────
# A. is_private_or_internal: private + reserved -> True; public -> False
# ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("addr", [PRIVATE_A, PRIVATE_B, LOOPBACK, LINKLOCAL])
def test_is_private_or_internal_true_for_rfc1918_loopback_linklocal(addr):
    assert is_private_or_internal(addr) is True


def test_is_private_or_internal_false_for_public_8888():
    assert is_private_or_internal(PUBLIC_ADDR) is False


@pytest.mark.parametrize("addr", ["*", "0.0.0.0", "::", "", "not-an-ip"])
def test_is_private_or_internal_false_for_wildcards_and_garbage(addr):
    assert is_private_or_internal(addr) is False


def test_is_private_or_internal_handles_none():
    assert is_private_or_internal(None) is False  # type: ignore[arg-type]


def test_extract_ipv4_boundary_guards():
    text = f"Two addrs: {PRIVATE_A} and {PUBLIC_ADDR} in v1.2.3.4.5 marker"
    found = extract_ipv4(text)
    assert PRIVATE_A in found
    assert PUBLIC_ADDR in found
    # A dotted version like 1.2.3.4.5 must not steal a 4-octet group.
    assert "1.2.3.4" not in found
    assert "2.3.4.5" not in found


# ────────────────────────────────────────────────────────────────────
# B + C. normalize_private_ip_wording: 2-tuple contract, private-only
# ────────────────────────────────────────────────────────────────────

def test_normalize_private_ip_wording_returns_two_tuple():
    out = normalize_private_ip_wording(f"external IP {PRIVATE_A}")
    assert isinstance(out, tuple) and len(out) == 2
    new_text, rewritten = out
    assert isinstance(new_text, str)
    assert isinstance(rewritten, list)


def test_normalize_rewrites_private_addresses_only():
    private_text = f"Connection to external IP {PRIVATE_A} observed."
    public_text = f"Connection to external IP {PUBLIC_ADDR} observed."

    new_priv, rewritten_priv = normalize_private_ip_wording(private_text)
    new_pub, rewritten_pub = normalize_private_ip_wording(public_text)

    assert f"private/internal address {PRIVATE_A}" in new_priv
    assert f"external IP {PRIVATE_A}" not in new_priv
    assert rewritten_priv == [PRIVATE_A]

    # Public address: exact match, not added to rewritten list.
    assert new_pub == public_text
    assert rewritten_pub == []


def test_normalize_handles_external_address_phrasing():
    text = f"external address {PRIVATE_B} listening on TCP/445"
    new, rewritten = normalize_private_ip_wording(text)
    assert f"private/internal address {PRIVATE_B}" in new
    assert rewritten == [PRIVATE_B]


def test_normalize_rewritten_list_is_first_seen_and_deduped():
    text = (
        f"external IP {PRIVATE_A}, external IP {PRIVATE_B}, "
        f"external IP {PRIVATE_A} again."
    )
    _, rewritten = normalize_private_ip_wording(text)
    assert rewritten == [PRIVATE_A, PRIVATE_B]


def test_normalize_handles_empty_and_non_string():
    assert normalize_private_ip_wording("") == ("", [])
    assert normalize_private_ip_wording(None) == ("", [])  # type: ignore[arg-type]


# ────────────────────────────────────────────────────────────────────
# D. _NETWORK_LISTENER_TOOLS contains the real runtime tool name.
# ────────────────────────────────────────────────────────────────────

def test_network_listener_tools_contains_vol_netscan():
    assert "vol_netscan" in _NETWORK_LISTENER_TOOLS


# ────────────────────────────────────────────────────────────────────
# Synthetic finding fixture (no case-specific values).
# ────────────────────────────────────────────────────────────────────

def _network_finding(
    severity: str = "CRITICAL",
    *,
    self_corrected: bool = True,
    source_tools: list[str] | None = None,
) -> dict:
    return {
        "finding_id": "F999",
        "title": (
            f"Suspicious connection to external IP {PRIVATE_A}"
        ),
        "artifact": (
            f"Established connection from {EXAMPLE_PROC} "
            f"(PID {EXAMPLE_PID_A}) to external IP {PRIVATE_A}"
        ),
        "description": (
            f"Multiple suspicious network connections to external IP "
            f"{PRIVATE_A} from {EXAMPLE_PROC} (PID {EXAMPLE_PID_A})."
        ),
        "summary": f"{EXAMPLE_PROC} -> external IP {PRIVATE_A}",
        "narrative": (
            f"PID {EXAMPLE_PID_B} reached external IP {PRIVATE_B} "
            f"during the observation window."
        ),
        "details": f"external IP {PRIVATE_A} contacted by host service.",
        "source_tools": (
            list(source_tools) if source_tools is not None else ["vol_netscan"]
        ),
        "self_corrected": self_corrected,
        "confidence_level": "LOW",
        "severity": severity,
        "claims": [
            {
                "type": "connection",
                "foreign_addr": PRIVATE_A,
                "foreign_port": 445,
                "process": EXAMPLE_PROC,
                "pid": EXAMPLE_PID_A,
            },
        ],
    }


# ────────────────────────────────────────────────────────────────────
# E. apply_post_step13_normalization rewrites every human-readable field.
# ────────────────────────────────────────────────────────────────────

def test_apply_post_step13_normalization_rewrites_all_fields():
    f = _network_finding(severity="LOW", self_corrected=False)
    audit = apply_post_step13_normalization([f])

    for key in ("title", "artifact", "description", "summary", "narrative",
                "details"):
        assert "external IP" not in f[key], (
            f"{key} still says 'external IP' after normalization: {f[key]!r}"
        )
    assert f"private/internal address {PRIVATE_A}" in f["title"]
    assert f"private/internal address {PRIVATE_A}" in f["artifact"]
    assert f"private/internal address {PRIVATE_A}" in f["description"]
    assert f"private/internal address {PRIVATE_A}" in f["summary"]
    assert f"private/internal address {PRIVATE_B}" in f["narrative"]
    assert f"private/internal address {PRIVATE_A}" in f["details"]

    # Audit dict records every rewrite.
    assert audit["wording_rewrites"]
    rewritten_addrs = audit["wording_rewrites"][0]["addrs"]
    assert PRIVATE_A in rewritten_addrs
    assert PRIVATE_B in rewritten_addrs


def test_apply_post_step13_normalization_skips_absent_and_non_string():
    f = _network_finding(severity="LOW", self_corrected=False)
    # Wipe some optional fields, set one to non-string.
    f.pop("narrative", None)
    f["details"] = 12345  # type: ignore[assignment]
    apply_post_step13_normalization([f])  # must not raise
    # Fields that survive are still rewritten.
    assert f"private/internal address {PRIVATE_A}" in f["description"]


# ────────────────────────────────────────────────────────────────────
# F. Cap + route-out flags must be visible on the finding.
# ────────────────────────────────────────────────────────────────────

def test_self_corrected_single_tool_caps_and_sets_route_out_flags():
    f = _network_finding(severity="CRITICAL")
    audit = cap_self_corrected_single_tool(f)

    assert audit is not None
    assert audit["severity_before"] == "CRITICAL"
    assert audit["severity_after"] == "LOW"
    assert audit["semantic_support"] is False
    assert audit["reason"] == REASON_SELF_CORRECTED_SINGLE_TOOL

    assert f["severity"] == "LOW"
    assert f["severity_ledger_cap_applied"] is True
    assert f["severity_ledger_route_out"] is True
    assert REASON_SELF_CORRECTED_SINGLE_TOOL in (
        f.get("severity_ledger_route_out_reason") or ""
    )
    # The cap reason carries the offending tool name.
    assert f["severity_cap_reason"].startswith(
        REASON_SELF_CORRECTED_SINGLE_TOOL
    )
    assert "vol_netscan" in f["severity_cap_reason"]


def test_two_tools_is_not_capped_and_no_route_out_flag():
    f = _network_finding(severity="CRITICAL", source_tools=[
        "vol_netscan", "parse_event_logs",
    ])
    audit = cap_self_corrected_single_tool(f)
    assert audit is None
    assert f["severity"] == "CRITICAL"
    assert f.get("severity_ledger_route_out") is None
    assert f.get("severity_ledger_cap_applied") is None


def test_non_self_corrected_single_tool_is_not_capped():
    f = _network_finding(severity="CRITICAL", self_corrected=False)
    audit = cap_self_corrected_single_tool(f)
    assert audit is None
    assert f["severity"] == "CRITICAL"
    assert f.get("severity_ledger_route_out") is None


def test_self_corrected_single_tool_already_low_still_route_outs():
    f = _network_finding(severity="LOW")
    cap_self_corrected_single_tool(f)
    # No severity change but the flags are still set so disposition
    # can fail-closed downstream.
    assert f["severity"] == "LOW"
    assert f["severity_ledger_cap_applied"] is True
    assert f["severity_ledger_route_out"] is True


# ────────────────────────────────────────────────────────────────────
# G. Disposition reads severity_ledger_route_out and fails closed.
# ────────────────────────────────────────────────────────────────────

def test_disposition_routes_out_on_severity_ledger_flag():
    f = _network_finding(severity="CRITICAL")
    cap_self_corrected_single_tool(f)
    bucket, reasons = derive_final_disposition(f, None, None)
    assert bucket == "suspicious_needs_review"
    assert any("severity_ledger_route_out" in r for r in reasons)


def test_disposition_without_flag_is_not_routed_out_by_this_gate():
    f = _network_finding(severity="LOW", self_corrected=False)
    # No cap call -> no severity_ledger_route_out tag. The disposition
    # may still route this elsewhere for unrelated reasons, but the
    # severity-ledger gate itself must not be the cause.
    bucket, reasons = derive_final_disposition(f, None, None)
    assert not any(
        "severity_ledger_route_out" in r for r in reasons
    ), f"unexpected severity_ledger_route_out in reasons: {reasons}"


# ────────────────────────────────────────────────────────────────────
# H. Drift gate proves LOW cannot silently rise without an allowed reason.
# ────────────────────────────────────────────────────────────────────

def test_drift_gate_flags_low_to_critical_without_allowed_reason():
    f = _network_finding(severity="LOW", self_corrected=False)
    ledger = record_after_step13([f])
    escalated = copy.deepcopy(f)
    escalated["severity"] = "CRITICAL"

    drift = verify_no_drift(ledger, [escalated], allowed_reasons=None)
    assert len(drift) == 1
    assert drift[0]["finding_id"] == "F999"
    assert drift[0]["severity_before"] == "LOW"
    assert drift[0]["severity_after"] == "CRITICAL"


def test_drift_gate_passes_when_allowed_reason_provided():
    f = _network_finding(severity="LOW", self_corrected=False)
    ledger = record_after_step13([f])
    escalated = copy.deepcopy(f)
    escalated["severity"] = "HIGH"
    drift = verify_no_drift(
        ledger, [escalated],
        allowed_reasons={"F999": ["explicit_review_upgrade"]},
    )
    assert drift == []


def test_drift_gate_allows_downward_moves_without_reason():
    f = _network_finding(severity="HIGH", self_corrected=False)
    ledger = record_after_step13([f])
    downward = copy.deepcopy(f)
    downward["severity"] = "LOW"
    drift = verify_no_drift(ledger, [downward], allowed_reasons=None)
    assert drift == []


# ────────────────────────────────────────────────────────────────────
# I. Owned-file literal scan.
# ────────────────────────────────────────────────────────────────────

def test_severity_ledger_source_is_free_of_cidr_tables_and_172_16():
    src = (
        Path(__file__).resolve().parent.parent.parent
        / "src" / "sift_sentinel" / "analysis" / "severity_ledger.py"
    )
    text = src.read_text()
    bad_terms = ("IPv4Network", "_INTERNAL_NETWORKS")
    for term in bad_terms:
        assert term not in text, (
            f"severity_ledger.py must not contain {term!r}"
        )
    # Token "172.16." must not appear anywhere in the source.
    assert re.search(r"172\.16\.", text) is None, (
        "severity_ledger.py must not contain the 172.16. token"
    )


# ────────────────────────────────────────────────────────────────────
# Integration: full apply_post_step13_normalization on a synthetic finding.
# ────────────────────────────────────────────────────────────────────

def test_full_normalization_caps_rewrites_and_drift_gate_is_clean():
    f = _network_finding(severity="CRITICAL")
    apply_post_step13_normalization([f])

    # Wording rewritten across every field.
    for key in ("title", "artifact", "description", "summary", "narrative",
                "details"):
        assert "external IP" not in f[key]

    # Cap + route-out flags set.
    assert f["severity"] == "LOW"
    assert f["severity_ledger_cap_applied"] is True
    assert f["severity_ledger_route_out"] is True

    # Drift gate clean against the post-normalization snapshot.
    ledger = record_after_step13([f])
    drift = verify_no_drift(ledger, [f], allowed_reasons=None)
    assert drift == []


def test_normalization_is_idempotent():
    f = _network_finding(severity="CRITICAL")
    apply_post_step13_normalization([f])
    first_severity = f["severity"]
    first_desc = f["description"]
    audit2 = apply_post_step13_normalization([f])
    assert f["severity"] == first_severity
    assert f["description"] == first_desc
    assert audit2["caps"] == []
    assert audit2["wording_rewrites"] == []
