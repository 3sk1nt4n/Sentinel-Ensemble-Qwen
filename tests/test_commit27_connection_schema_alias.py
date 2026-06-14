"""Commit 27: regression guards for connection-claim schema alignment.

Ensures:
  L27-1  structural: normalize_claims has remote_ip/remote_port/foreign bridges
  L27-2  behavioral: remote_ip + remote_port alias maps to foreign_addr/port
  L27-3a behavioral: foreign "ip:port" splits to foreign_addr + foreign_port
  L27-3b behavioral A2: foreign bare ip -> foreign_addr only, no foreign_port
  L27-3c behavioral: foreign "ip:abc" malformed port -> addr set, port absent
  L27-3d behavioral guard: foreign "" empty -> no foreign_addr injected
  L27-3e behavioral guard: foreign "::1" bare IPv6 -> claim unchanged (skip)
  L27-4  regression: existing foreign_ip and remote_addr aliases still work
  L27-5  prompt alignment: Inv2 + SC strategies use canonical schema only
"""
from __future__ import annotations

from pathlib import Path

from sift_sentinel.validation.normalize_claims import normalize_claims


def _wrap(*claims):
    return [{"claims": list(claims)}]


def test_L27_1_normalizer_source_has_all_new_bridges():
    """Structural: normalize_claims source contains all new C27 bridges."""
    src = Path('src/sift_sentinel/validation/normalize_claims.py').read_text()
    assert '"remote_ip" in claim' in src, "C27: remote_ip bridge missing"
    assert '"remote_port" in claim' in src, "C27: remote_port bridge missing"
    assert '"foreign" in claim' in src, "C27: foreign bridge missing"
    assert 'rpartition(":")' in src, "C27: IPv4 split missing"
    assert '"]:" in raw_foreign' in src, "C27: IPv6 bracketed guard missing"


def test_L27_2_remote_ip_and_remote_port_bridge():
    """Behavioral: Inv2-style remote_ip + remote_port normalize to canonical."""
    findings = _wrap({
        "type": "connection", "pid": 100, "process": "x.exe",
        "remote_ip": "1.2.3.4", "remote_port": 443,
    })
    result = normalize_claims(findings)
    claim = result[0]["claims"][0]
    assert claim.get("foreign_addr") == "1.2.3.4", f"remote_ip not bridged: {claim}"
    assert claim.get("foreign_port") == 443, f"remote_port not bridged: {claim}"
    assert "remote_ip" not in claim, "legacy remote_ip leaked"
    assert "remote_port" not in claim, "legacy remote_port leaked"


def test_L27_3a_foreign_alias_splits_ipv4_with_port():
    """Behavioral: foreign 'ip:port' splits to foreign_addr + foreign_port."""
    findings = _wrap({
        "type": "connection", "pid": 100, "process": "x.exe",
        "foreign": "1.2.3.4:8080",
    })
    result = normalize_claims(findings)
    claim = result[0]["claims"][0]
    assert claim.get("foreign_addr") == "1.2.3.4", f"split addr failed: {claim}"
    assert claim.get("foreign_port") == 8080, f"split port failed: {claim}"
    assert "foreign" not in claim, "legacy foreign key leaked"


def test_L27_3b_foreign_bare_ip_no_port_A2_graceful():
    """Behavioral A2: bare ip (no colon) sets foreign_addr only."""
    findings = _wrap({
        "type": "connection", "pid": 100, "process": "x.exe",
        "foreign": "1.2.3.4",
    })
    result = normalize_claims(findings)
    claim = result[0]["claims"][0]
    assert claim.get("foreign_addr") == "1.2.3.4", f"bare ip failed: {claim}"
    assert "foreign_port" not in claim, f"foreign_port leaked when port absent: {claim}"


def test_L27_3c_foreign_malformed_port_graceful():
    """Behavioral guard: malformed port (non-int) -> addr set, port absent."""
    findings = _wrap({
        "type": "connection", "pid": 100, "process": "x.exe",
        "foreign": "1.2.3.4:abc",
    })
    result = normalize_claims(findings)
    claim = result[0]["claims"][0]
    assert claim.get("foreign_addr") == "1.2.3.4", f"malformed port lost addr: {claim}"
    assert "foreign_port" not in claim, f"foreign_port injected from bad int: {claim}"


def test_L27_3d_foreign_empty_string_no_injection():
    """Behavioral guard: empty string foreign -> no foreign_addr injection.
    Empty string is strictly worse than absent key (validator false-match risk)."""
    findings = _wrap({
        "type": "connection", "pid": 100, "process": "x.exe",
        "foreign": "",
    })
    result = normalize_claims(findings)
    claim = result[0]["claims"][0]
    assert "foreign_addr" not in claim, (
        f"empty string foreign injected empty foreign_addr: {claim}"
    )
    assert claim.get("foreign_port") is None or "foreign_port" not in claim


def test_L27_3e_foreign_bare_ipv6_skipped():
    """Behavioral guard: bare IPv6 (multi-colon no brackets) skipped.
    Prevents '::1' mis-splitting to foreign_addr=':' foreign_port=1."""
    findings = _wrap({
        "type": "connection", "pid": 100, "process": "x.exe",
        "foreign": "::1",
    })
    result = normalize_claims(findings)
    claim = result[0]["claims"][0]
    # Guard 4 (else) skips - neither addr nor port set
    assert claim.get("foreign_addr") != ":", f"bare IPv6 mis-split: {claim}"
    assert "foreign_port" not in claim or claim.get("foreign_port") != 1, (
        f"bare IPv6 injected bogus port: {claim}"
    )


def test_L27_4_existing_aliases_regression():
    """Regression: foreign_ip and remote_addr still bridge to foreign_addr."""
    findings = _wrap({
        "type": "connection", "pid": 100, "process": "x.exe",
        "foreign_ip": "1.2.3.4",
    })
    result = normalize_claims(findings)
    assert result[0]["claims"][0].get("foreign_addr") == "1.2.3.4"

    findings = _wrap({
        "type": "connection", "pid": 100, "process": "x.exe",
        "remote_addr": "5.6.7.8",
    })
    result = normalize_claims(findings)
    assert result[0]["claims"][0].get("foreign_addr") == "5.6.7.8"


def test_L27_5_prompts_use_canonical_schema():
    """Regression: Inv2 + SC strategies teach canonical foreign_addr/port only.
    Legacy aliases still live in normalize_claims as insurance; prompts must not."""
    inv2_src = Path('src/sift_sentinel/coordinator.py').read_text()
    strat_src = Path('src/sift_sentinel/correction/strategies.py').read_text()

    # Positive: Inv2 teaches canonical schema (prose + example)
    assert 'foreign_addr + foreign_port' in inv2_src, (
        "Inv2 prompt prose lost canonical foreign_addr + foreign_port"
    )
    assert '"foreign_addr": "1.2.3.4"' in inv2_src, (
        "Inv2 prompt example lost canonical foreign_addr"
    )
    assert '"foreign_port": 443' in inv2_src, (
        "Inv2 prompt example lost canonical foreign_port"
    )

    # Positive: SC strategies teaches canonical schema
    assert '"foreign_addr": "<ip>"' in strat_src, (
        "SC strategies lost canonical foreign_addr"
    )
    assert '"foreign_port": <int>' in strat_src, (
        "SC strategies lost canonical foreign_port"
    )
    assert '"process": "<name>"' in strat_src, (
        "SC strategies lost required process field"
    )

    # Negative: legacy prompt examples must be gone from prompt TEXT
    assert 'remote_ip + remote_port' not in inv2_src, (
        "Inv2 prose still teaches remote_ip + remote_port legacy schema"
    )
    assert '"remote_ip": "1.2.3.4"' not in inv2_src, (
        "Inv2 example still teaches legacy remote_ip"
    )
    assert '"local": "<ip:port>", "foreign": "<ip:port>"' not in strat_src, (
        "SC strategies still teaches legacy local/foreign pair"
    )
