"""Conclusive structural signal: a kernel driver loaded from a non-standard path.

A kernel-mode driver (.sys) whose service ImagePath / Event-7045 install path is
OUTSIDE the System32 driver store, and is not a core Windows kernel module, is a
kernel-rootkit loading primitive (MITRE T1014 / T1543.003). Legitimate drivers
always load from System32\\drivers; a .sys anywhere else has no benign
explanation -- so this is forensically CONCLUSIVE on its own and may auto-confirm
(behind SIFT_CONCLUSIVE_CONFIRM) without any corroboration count.

PROPERTY-BASED: every value here is synthetic and relabelled. The predicate is
the driver-path SHAPE + kernel service type, never a product / case / hash / PID.
"""
from __future__ import annotations

from sift_sentinel.analysis.malicious_semantics import (
    CONCLUSIVE_STRUCTURAL_SIGNALS,
    MALICIOUS_SEMANTIC_SIGNALS,
    has_malicious_semantic,
    match_kernel_driver_nonstandard_path,
)


def _reg(value_data, value_name="ImagePath", service="genericsvc"):
    return {
        "fact_type": "registry_persistence_fact",
        "registry_path": r"HKLM\SYSTEM\ControlSet001\Services\%s" % service,
        "normalized_registry_path":
            "hklm/system/controlset001/services/%s/imagepath" % service,
        "value_name": value_name,
        "value_data": value_data,
        "service_name": service,
    }


# ── the matcher: fires on the rootkit shape ──────────────────────────────

def test_fires_on_sys_driver_in_windows_root():
    assert match_kernel_driver_nonstandard_path(_reg(r"\??\C:\windows\drv01.sys")) is True


def test_fires_on_sys_driver_in_temp():
    assert match_kernel_driver_nonstandard_path(_reg(r"C:\Users\x\AppData\Local\Temp\k.sys")) is True


def test_fires_with_systemroot_prefix():
    assert match_kernel_driver_nonstandard_path(_reg(r"\SystemRoot\bad.sys")) is True


# ── the matcher: does NOT fire on legitimate shapes ──────────────────────

def test_no_fire_on_driver_store():
    assert match_kernel_driver_nonstandard_path(
        _reg(r"\??\C:\Windows\System32\drivers\legit.sys")) is False


def test_no_fire_on_driverstore_filerepository():
    assert match_kernel_driver_nonstandard_path(
        _reg(r"C:\Windows\System32\DriverStore\FileRepository\x\vendor.sys")) is False


def test_no_fire_on_exe_user_service():
    # McAfee / Velociraptor / F-Response shape: a .exe service is NOT a kernel
    # driver -> never a kernel-rootkit primitive, regardless of path
    assert match_kernel_driver_nonstandard_path(
        _reg(r"C:\Program Files\Vendor\agent.exe")) is False
    assert match_kernel_driver_nonstandard_path(
        _reg(r"C:\Windows\some_service.exe")) is False


def test_no_fire_on_core_kernel_module():
    assert match_kernel_driver_nonstandard_path(_reg(r"C:\Windows\ntoskrnl.sys")) is False
    assert match_kernel_driver_nonstandard_path(_reg(r"\SystemRoot\tcpip.sys")) is False


def test_no_fire_when_no_imagepath_value():
    # a Start/Type value with no path must not fire
    assert match_kernel_driver_nonstandard_path(
        _reg("3", value_name="Start")) is False


def test_no_fire_on_unrelated_fact():
    assert match_kernel_driver_nonstandard_path(
        {"fact_type": "process_fact", "image_name": "svchost.exe"}) is False


# ── registration + has_malicious_semantic recognises it ──────────────────

def test_signal_registered_and_conclusive():
    assert "kernel_driver_nonstandard_path" in MALICIOUS_SEMANTIC_SIGNALS
    assert "kernel_driver_nonstandard_path" in CONCLUSIVE_STRUCTURAL_SIGNALS


def test_has_semantic_fires_via_declared():
    f = {"finding_id": "F1",
         "malicious_semantic_signals": ["kernel_driver_nonstandard_path"]}
    ok, sigs = has_malicious_semantic(f, {})
    assert ok and "kernel_driver_nonstandard_path" in sigs


def test_has_semantic_fires_via_matcher_on_registry_fact():
    f = {"finding_id": "F2",
         "claims": [_reg(r"\??\C:\windows\q.sys")]}
    ok, sigs = has_malicious_semantic(f, {})
    assert ok and "kernel_driver_nonstandard_path" in sigs


# ── metamorphic: relabel the driver name -> identical verdict ────────────

def test_metamorphic_driver_name_irrelevant():
    a = match_kernel_driver_nonstandard_path(_reg(r"C:\windows\alpha.sys", service="alpha"))
    b = match_kernel_driver_nonstandard_path(_reg(r"C:\windows\beta.sys", service="beta"))
    assert a is b is True
