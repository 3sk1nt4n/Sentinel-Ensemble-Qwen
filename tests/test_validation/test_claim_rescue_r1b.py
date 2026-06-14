"""R1b claim-rescue: findings blocked with "no recognized claim types" rebind
onto EXISTING typed indexes/facts so they are ADJUDICATED (validated, routed,
dispositioned) instead of silently dropped at Step 10.

Additive-only contract: every rescue either produces a typed MATCH or leaves
the prior verdict unchanged (abstain / existing MISMATCH). No rescue invents
evidence, no rescue path can auto-confirm (disposition gates are untouched).
Universal: keyed on claim SHAPE (bare token, privilege grammar, the pipeline's
own ttp-tag grammar) -- never a case/product/host name.

Kill-switch: SIFT_CLAIM_RESCUE_R1B=0 disables every rescue.
"""
import copy

from sift_sentinel.validation.normalize_claims import normalize_claims
from sift_sentinel.validation.typed_validator import (
    TypedEvidenceDB,
    typed_check_claim,
)
from sift_sentinel.validation.validator import validate_finding


def _tdb(typed_facts, indexes):
    return TypedEvidenceDB({"typed_facts": typed_facts, "indexes": indexes})


# ── synthetic typed-fact payloads (case-neutral tokens) ──────────────────
PRIV_PAYLOAD = {
    "typed_facts": {"privilege_fact": [{
        "fact_id": "privilege_fact-0000001",
        "fact_type": "privilege_fact",
        "process_name": "GammaIndexer.exe",
        "pid": 4242,
        "privilege": "SeImpersonatePrivilege",
        "enabled": True,
    }]},
    "indexes": {"by_pid": {"4242": ["privilege_fact-0000001"]}},
}

SVC_PAYLOAD = {
    "typed_facts": {"service_fact": [{
        "fact_id": "service_fact-0000001",
        "fact_type": "service_fact",
        "service_name": "examplesvc",
        "state": "RUNNING",
    }]},
    "indexes": {"by_service_name": {"examplesvc": ["service_fact-0000001"]}},
}

PROC_PAYLOAD = {
    "typed_facts": {"process_fact": [{
        "fact_id": "process_fact-0000001",
        "fact_type": "process_fact",
        "process_name": "AlphaProtoHost.exe",
        "pid": 777,
    }]},
    "indexes": {"by_pid": {"777": ["process_fact-0000001"]}},
}

PS_PAYLOAD = {
    "typed_facts": {"powershell_command_fact": [{
        "fact_id": "powershell_command_fact-0000001",
        "fact_type": "powershell_command_fact",
        "command": "Remove-Item -Recurse $env:TEMP\\staging",
        "ttp_tags": ["anti_forensics"],
    }]},
    "indexes": {"by_ttp_tag": {
        "anti_forensics": ["powershell_command_fact-0000001"]}},
}


def _one_claim(finding):
    return finding["claims"][0]


# ── 1. privilege process-recovery (F035/F036 shape) ──────────────────────
def test_privilege_claim_recovers_process_token_and_matches():
    finding = {
        "finding_id": "T1",
        "title": "Elevated privilege context: process with sensitive privileges",
        "description": "synthetic",
        "claims": [{
            "type": "process_privilege_enabled",
            "privilege_name": "SeImpersonate",
            "enabled": True,
            "value": "GammaIndexer with elevated privileges SeImpersonate",
            "artifact": "GammaIndexer SeImpersonate enabled",
        }],
    }
    out = normalize_claims([finding])[0]
    claim = _one_claim(out)
    assert claim["process"] == "GammaIndexer"
    verdict = typed_check_claim(claim, _tdb(
        PRIV_PAYLOAD["typed_facts"], PRIV_PAYLOAD["indexes"]))
    assert verdict is not None and verdict[0] == "MATCH"


def test_privilege_claim_existing_process_never_clobbered():
    finding = {
        "finding_id": "T2",
        "title": "x", "description": "x",
        "claims": [{
            "type": "process_privilege_enabled",
            "privilege_name": "SeImpersonate",
            "enabled": True,
            "process": "OtherProc.exe",
            "value": "GammaIndexer with elevated privileges SeImpersonate",
        }],
    }
    out = normalize_claims([finding])[0]
    assert _one_claim(out)["process"] == "OtherProc.exe"


# ── 2. bare-token service rescue (F045 shape) ────────────────────────────
def test_bare_token_with_service_cue_retypes_to_service_and_matches():
    finding = {
        "finding_id": "T3",
        "title": "Service installation with non-standard path: examplesvc",
        "description": "synthetic service install observation",
        "claims": [{"type": "path", "value": "examplesvc",
                    "artifact": "examplesvc"}],
    }
    out = normalize_claims([finding])[0]
    claim = _one_claim(out)
    assert claim["type"] == "service"
    assert claim["service_name"] == "examplesvc"
    assert claim.get("rescued_from") == "bare_token_path"
    verdict = typed_check_claim(claim, _tdb(
        SVC_PAYLOAD["typed_facts"], SVC_PAYLOAD["indexes"]))
    assert verdict is not None and verdict[0] == "MATCH"


# ── 3. bare-token process rescue (F009/F038/F046 shape) ──────────────────
def test_bare_token_without_service_cue_retypes_to_process_exists():
    finding = {
        "finding_id": "T4",
        "title": "Process view inconsistency detected for AlphaProtoHost",
        "description": "psxview cross-view inconsistency, synthetic",
        "claims": [{"type": "path", "value": "AlphaProtoHost",
                    "artifact": "AlphaProtoHost"}],
    }
    out = normalize_claims([finding])[0]
    claim = _one_claim(out)
    assert claim["type"] == "process_exists"
    assert claim["process"] == "AlphaProtoHost"
    verdict = typed_check_claim(claim, _tdb(
        PROC_PAYLOAD["typed_facts"], PROC_PAYLOAD["indexes"]))
    assert verdict is not None and verdict[0] == "MATCH"
    assert "process-name" in verdict[1]


def test_process_exists_name_scan_abstains_on_unknown_name():
    claim = {"type": "process_exists", "process": "NoSuchImage"}
    verdict = typed_check_claim(claim, _tdb(
        PROC_PAYLOAD["typed_facts"], PROC_PAYLOAD["indexes"]))
    assert verdict is None  # abstain -- additive-only, never a new MISMATCH


def test_process_exists_with_pid_keeps_existing_behavior():
    claim = {"type": "process_exists", "pid": 777}
    verdict = typed_check_claim(claim, _tdb(
        PROC_PAYLOAD["typed_facts"], PROC_PAYLOAD["indexes"]))
    assert verdict is not None and verdict[0] == "MATCH"


def test_bare_token_without_any_cue_stays_path():
    # Preserves the TypeAliasRemapping pin: a context-free bare token from an
    # artifact/raw alias keeps the plain "path" type -- no retype.
    finding = {
        "finding_id": "T4b",
        "title": "x", "description": "x",
        "claims": [{"type": "artifact", "name": "prefetch"}],
    }
    out = normalize_claims([finding])[0]
    assert _one_claim(out)["type"] == "path"


# ── 4. real paths are never retyped ──────────────────────────────────────
def test_real_path_claim_untouched():
    finding = {
        "finding_id": "T5",
        "title": "Service binary on disk", "description": "x",
        "claims": [{"type": "path",
                    "value": "C:\\Windows\\System32\\example.exe"}],
    }
    out = normalize_claims([finding])[0]
    assert _one_claim(out)["type"] == "path"


# ── 5. ttp-tag family match (F021 shape) ─────────────────────────────────
def test_ttp_tag_family_prefix_matches():
    claim = {"type": "powershell_command",
             "ttp_tag": "anti_forensics_tool_execution"}
    verdict = typed_check_claim(claim, _tdb(
        PS_PAYLOAD["typed_facts"], PS_PAYLOAD["indexes"]))
    assert verdict is not None and verdict[0] == "MATCH"
    assert "family" in verdict[1]


def test_ttp_tag_unrelated_still_mismatches():
    claim = {"type": "powershell_command", "ttp_tag": "credential_access"}
    verdict = typed_check_claim(claim, _tdb(
        PS_PAYLOAD["typed_facts"], PS_PAYLOAD["indexes"]))
    assert verdict is not None and verdict[0] == "MISMATCH"


def test_ttp_tag_family_requires_underscore_boundary():
    # "anti" must NOT family-match "antimalware_scan" (no word boundary).
    payload = copy.deepcopy(PS_PAYLOAD)
    payload["typed_facts"]["powershell_command_fact"][0]["ttp_tags"] = ["anti"]
    payload["indexes"]["by_ttp_tag"] = {
        "anti": ["powershell_command_fact-0000001"]}
    claim = {"type": "powershell_command", "ttp_tag": "antimalware_scan"}
    verdict = typed_check_claim(claim, _tdb(
        payload["typed_facts"], payload["indexes"]))
    assert verdict is not None and verdict[0] == "MISMATCH"


# ── 6. kill-switch disables every rescue ─────────────────────────────────
def test_kill_switch_disables_rescues(monkeypatch):
    monkeypatch.setenv("SIFT_CLAIM_RESCUE_R1B", "0")
    finding = {
        "finding_id": "T6",
        "title": "Service installation: examplesvc", "description": "x",
        "claims": [{"type": "path", "value": "examplesvc",
                    "artifact": "examplesvc"}],
    }
    out = normalize_claims([finding])[0]
    assert _one_claim(out)["type"] == "path"  # no retype
    ps_claim = {"type": "powershell_command",
                "ttp_tag": "anti_forensics_tool_execution"}
    verdict = typed_check_claim(ps_claim, _tdb(
        PS_PAYLOAD["typed_facts"], PS_PAYLOAD["indexes"]))
    assert verdict is not None and verdict[0] == "MISMATCH"


# ── 7. end-to-end: the blocked shape now validates (adjudicated) ─────────
def test_e2e_blocked_shape_no_longer_unrecognized():
    finding = {
        "finding_id": "T7",
        "title": "Process view inconsistency detected for AlphaProtoHost",
        "description": "psxview cross-view inconsistency, synthetic",
        "claims": [{"type": "path", "value": "AlphaProtoHost",
                    "artifact": "AlphaProtoHost"}],
    }
    normalized = normalize_claims([finding])[0]
    result = validate_finding(
        normalized, {}, evidence_db={
            "typed_facts": PROC_PAYLOAD["typed_facts"],
            "indexes": PROC_PAYLOAD["indexes"],
        })
    assert result.get("detail") != "no recognized claim types"
    assert any(c.get("result") == "MATCH" for c in result.get("checks") or [])
