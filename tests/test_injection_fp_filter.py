"""Deterministic JIT/.NET RWX false-positive discriminator (downgrade-only).

Cases mirror the live Acme run: SearchApp/LockApp (clean JIT/UWP hosts -> clear)
vs MsMpEng/dllhost (not JIT hosts -> stay) vs a real injected PE / module-less
shellcode (payload present -> never suppressed). Universal: technique + structure.
"""
from sift_sentinel.analysis.injection_fp_filter import (
    classify_benign_jit_rwx,
    is_managed_jit_host,
)


def _f(corrob=False, char="code"):
    return {"injection_corroborated": corrob, "characterization": char}


# --- the clears (genuine JIT / UWP hosts, no payload, no corroborator) --------

def test_searchapp_chakra_jit_host_is_suppressed():
    ok, reason = classify_benign_jit_rwx(
        [_f(char="code")], dll_names=["chakra.dll", "ntdll.dll"],
        process_path="c:/program files/windowsapps/microsoft.windows.search_x/searchapp.exe")
    assert ok is True and reason == "benign_jit_rwx"


def test_lockapp_uwp_path_zero_fill_is_suppressed():
    ok, reason = classify_benign_jit_rwx(
        [_f(char="zero_fill")], dll_names=[],
        process_path="c:/windows/systemapps/microsoft.lockapp_cw5n1h2txyewy/lockapp.exe")
    assert ok is True and reason == "benign_jit_rwx"


# --- the safe non-clears (correctly stay flagged) -----------------------------

def test_defender_native_rwx_not_a_jit_host_stays():
    # MsMpEng: RWX is the AV engine, not JIT; no runtime DLL, not a UWP path.
    ok, reason = classify_benign_jit_rwx(
        [_f(char="code")], dll_names=["mpengine.dll", "ntdll.dll"],
        process_path="c:/programdata/microsoft/windows defender/platform/msmpeng.exe")
    assert ok is False and reason == "not_a_managed_jit_host"


# --- the safety rails: a real injection is NEVER suppressed -------------------

def test_injected_pe_payload_never_suppressed():
    # char=mz_pe -> injection_corroborated True -> stays even on a JIT host.
    ok, reason = classify_benign_jit_rwx(
        [_f(corrob=True, char="mz_pe")], dll_names=["clr.dll"],
        process_path="c:/windows/systemapps/x/app.exe")
    assert ok is False and reason == "payload_corroborated"


def test_module_less_shellcode_blind_spot_is_closed():
    # The hard case: manual-mapped shellcode in RWX, no DLL, inside a JIT host.
    # char=shellcode is detected by malfind characterization -> NOT suppressed.
    ok, reason = classify_benign_jit_rwx(
        [_f(corrob=False, char="shellcode")], dll_names=["chakra.dll"],
        process_path="c:/program files/windowsapps/x/app.exe")
    assert ok is False and reason == "payload_signature_present"


def test_jit_host_with_external_egress_stays():
    ok, reason = classify_benign_jit_rwx(
        [_f(char="code")], dll_names=["clr.dll"],
        process_path="c:/x/app.exe", has_external_egress=True)
    assert ok is False and reason == "external_egress_present"


def test_jit_host_with_unlinked_dll_stays():
    ok, reason = classify_benign_jit_rwx(
        [_f(char="code")], dll_names=["clr.dll"], process_path="",
        has_unlinked_dll=True)
    assert ok is False and reason == "unlinked_dll_present"


def test_jit_host_with_bad_parent_stays():
    ok, reason = classify_benign_jit_rwx(
        [_f(char="code")], dll_names=["coreclr.dll"], process_path="",
        has_ancestry_violation=True)
    assert ok is False and reason == "ancestry_violation_present"


def test_no_facts_is_not_suppressed():
    assert classify_benign_jit_rwx([], dll_names=["clr.dll"]) == (False, "no_injection_facts")


def test_is_managed_jit_host_helpers():
    assert is_managed_jit_host(["CLR.dll"]) is True
    assert is_managed_jit_host([], "C:/Windows/SystemApps/Microsoft.LockApp_x/LockApp.exe") is True
    assert is_managed_jit_host(["ntdll.dll"], "c:/windows/system32/dllhost.exe") is False
