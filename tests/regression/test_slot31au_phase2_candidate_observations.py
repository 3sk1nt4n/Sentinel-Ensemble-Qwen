"""slot31AV regression: candidate observations for phase2 typed_facts.

Tests mirror RUNTIME storage shape: raw_excerpt = JSON-encoded original
Vol3 record. Direct typed fields (privilege, process_name, etc.) are
stripped at storage; candidate observations read from raw_excerpt.
"""
import json
import secrets
from sift_sentinel.analysis.candidate_observations import (
    build_candidate_observations,
)


def _db(*facts):
    typed = {}
    for f in facts:
        typed.setdefault(f["fact_type"], []).append(f)
    return {"typed_facts": typed}


def _sig_present(payload, signal):
    return any(signal in c.get("signals", []) for c in payload["candidates"])


def _with_signal(payload, signal):
    return [c for c in payload["candidates"] if signal in c.get("signals", [])]


def _ua_fact(fact_id, key_path, name, rnd):
    return {
        "fact_id": fact_id, "fact_type": "userassist_fact",
        "source_tool": "vol_userassist",
        "record_ref": f"vol_userassist#{fact_id}",
        "entity_id": f"userassist:{rnd}",
        "raw_excerpt": json.dumps({"KeyPath": key_path, "Name": name}),
        "artifact": [rnd, "Key", name[:30]],
    }


def _priv_fact(fact_id, pid, proc, priv, attrs):
    return {
        "fact_id": fact_id, "fact_type": "privilege_fact",
        "source_tool": "vol_privileges",
        "record_ref": f"vol_privileges#{fact_id}",
        "entity_id": f"privilege:pid:{pid}:{priv}",
        "raw_excerpt": json.dumps({
            "PID": pid, "Process": proc, "Privilege": priv,
            "Attributes": attrs,
        }),
        "artifact": [proc[:32], priv[:40], attrs[:30]],
    }


def _ssdt_fact(fact_id, idx, module, symbol):
    return {
        "fact_id": fact_id, "fact_type": "ssdt_integrity_fact",
        "source_tool": "vol_ssdt", "record_ref": f"vol_ssdt#{fact_id}",
        "entity_id": f"ssdt:{idx}:{symbol}",
        "raw_excerpt": json.dumps({
            "Index": idx, "Module": module, "Symbol": symbol,
            "Address": 0,
        }),
        "artifact": [str(idx), module, symbol],
    }


def test_userassist_staging_path_emits():
    rnd = secrets.token_hex(4)
    payload = build_candidate_observations(_db(_ua_fact(
        "ua-1",
        r"ntuser.dat\Software\Microsoft\Windows\test",
        r"C:\Windows\Temp\app_" + rnd + ".exe",
        rnd,
    )))
    assert _sig_present(payload, "userassist_execution_from_staging")
    cands = _with_signal(payload, "userassist_execution_from_staging")
    assert cands
    assert cands[0]["candidate_type"] == "high_risk_persistence"


def test_userassist_clean_path_no_candidate():
    rnd = secrets.token_hex(4)
    payload = build_candidate_observations(_db(_ua_fact(
        "ua-2",
        r"ntuser.dat\Software\Microsoft\Windows\Settings",
        r"C:\Program Files\Microsoft\Office\WINWORD.EXE",
        rnd,
    )))
    assert not _sig_present(payload, "userassist_execution_from_staging")


def test_privilege_sensitive_enabled_non_baseline_emits():
    rnd = secrets.token_hex(4)
    payload = build_candidate_observations(_db(_priv_fact(
        "pr-1", 1000 + secrets.randbelow(50000),
        "p_" + rnd + ".exe",
        "SeDebugPrivilege", "Present,Enabled",
    )))
    assert _sig_present(payload, "sensitive_privilege_enabled_on_non_baseline")
    cands = _with_signal(payload, "sensitive_privilege_enabled_on_non_baseline")
    assert cands[0]["candidate_type"] == "elevated_privilege_context"


def test_privilege_sensitive_on_baseline_no_candidate():
    payload = build_candidate_observations(_db(_priv_fact(
        "pr-2", 1234, "svchost.exe",
        "SeDebugPrivilege", "Present,Enabled",
    )))
    assert not _sig_present(payload, "sensitive_privilege_enabled_on_non_baseline")


def test_privilege_held_not_enabled_no_candidate():
    rnd = secrets.token_hex(4)
    payload = build_candidate_observations(_db(_priv_fact(
        "pr-3", 5678, "p_" + rnd + ".exe",
        "SeDebugPrivilege", "Present",
    )))
    assert not _sig_present(payload, "sensitive_privilege_enabled_on_non_baseline")


def test_ssdt_non_kernel_module_emits():
    rnd = secrets.token_hex(4)
    payload = build_candidate_observations(_db(_ssdt_fact(
        f"ssdt-{rnd}", secrets.randbelow(500),
        "rk_" + rnd + ".sys", "Nt" + secrets.token_hex(4),
    )))
    assert _sig_present(payload, "kernel_ssdt_hook")
    cands = _with_signal(payload, "kernel_ssdt_hook")
    assert cands[0]["candidate_type"] == "kernel_rootkit_indicator"
    assert cands[0]["validation_ready"] is True


def test_ssdt_known_kernel_modules_no_candidate():
    for module in ["ntoskrnl", "win32k.sys", "hal.dll", "fastfat.sys", "ntfs.sys"]:
        rnd = secrets.token_hex(4)
        payload = build_candidate_observations(_db(_ssdt_fact(
            f"ssdt-x-{rnd}", secrets.randbelow(500),
            module, "Nt" + secrets.token_hex(4),
        )))
        assert not _sig_present(payload, "kernel_ssdt_hook"), (
            f"false positive for legitimate kernel module {module}"
        )


def test_ssdt_dataset_agnostic_random_modules():
    facts = []
    for _ in range(3):
        rnd = secrets.token_hex(4)
        facts.append(_ssdt_fact(
            f"ssdt-{rnd}", secrets.randbelow(500),
            "rk_" + rnd + ".sys", "Nt" + secrets.token_hex(4),
        ))
    payload = build_candidate_observations(_db(*facts))
    cands = _with_signal(payload, "kernel_ssdt_hook")
    assert len(cands) >= 3
    for c in cands:
        assert c["candidate_type"] == "kernel_rootkit_indicator"
