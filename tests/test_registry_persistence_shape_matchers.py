"""Structural registry-persistence malice matchers (Good-tier, universal).

The broad high_risk_persistence signal fires on 4077 rd01 registry_persistence
facts (mostly benign) so it is correctly NOT emit-eligible. The genuinely
malicious key-SHAPES need a narrow, emit-eligible sub-signal:

  * IFEO  <exe>\\Debugger  value present            -> debugger hijack, T1546.012
  * SafeBoot\\...\\AlternateShell != cmd.exe(default) -> safe-mode persist, T1547.006

Validated against the real rd01 record: the IFEO sethc.exe Debugger=cmd.exe is the
classic sticky-keys backdoor (must fire even though the target is a system binary),
while SafeBoot AlternateShell=cmd.exe is the OS DEFAULT (must NOT fire -- flagging
it would be a false positive). Universal: registry-key shape + the OS-defined
default value, never a case exe name (tests use synthetic exe names).
"""
from __future__ import annotations

from sift_sentinel.analysis.malicious_semantics import (
    match_ifeo_debugger_hijack,
    match_safeboot_alternateshell_persistence,
)


def _reg_fact(persistence_type, value_name, value_data, leaf="anyapp.exe"):
    key = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\%s\\%s" % (
        "Image File Execution Options" if persistence_type == "ifeo" else "Control\\SafeBoot",
        leaf,
    )
    return {
        "fact_type": "registry_persistence_fact",
        "persistence_type": persistence_type,
        "value_name": value_name,
        "value_data": value_data,
        "registry_path": key,
        "normalized_registry_path": key.lower().replace("\\", "/"),
        "canonical_entity_id": "reg:" + key.lower().replace("\\", "/"),
    }


def test_ifeo_debugger_value_flagged_for_any_target_exe():
    # ANY exe under IFEO with a Debugger value -> hijack. Synthetic exe + the
    # real-world payload (a system shell) must both fire.
    for payload in ("C:\\Windows\\System32\\cmd.exe", "c:\\users\\x\\evil.exe"):
        f = _reg_fact("ifeo", "Debugger", payload, leaf="anyapp.exe")
        assert match_ifeo_debugger_hijack(f) is True, payload


def test_ifeo_without_debugger_value_not_flagged():
    # GlobalFlag and other IFEO values are not the debugger-hijack primitive.
    f = _reg_fact("ifeo", "GlobalFlag", "0x100", leaf="foo.exe")
    assert match_ifeo_debugger_hijack(f) is False


def test_safeboot_alternateshell_default_not_flagged():
    # cmd.exe is the OS default AlternateShell -> NOT persistence (rd01 FP guard).
    f = _reg_fact("safeboot", "AlternateShell", "cmd.exe")
    assert match_safeboot_alternateshell_persistence(f) is False


def test_safeboot_alternateshell_nondefault_flagged():
    for payload in ("evil.exe", "C:\\Windows\\Temp\\x.exe", "powershell.exe"):
        f = _reg_fact("safeboot", "AlternateShell", payload)
        assert match_safeboot_alternateshell_persistence(f) is True, payload


def test_matchers_ignore_non_registry_and_other_persistence_types():
    assert match_ifeo_debugger_hijack({"fact_type": "process_fact", "name": "x"}) is False
    assert match_safeboot_alternateshell_persistence(_reg_fact("run", "Foo", "bar.exe")) is False
    # an IFEO matcher must not fire on a SafeBoot fact and vice-versa
    assert match_ifeo_debugger_hijack(_reg_fact("safeboot", "AlternateShell", "evil.exe")) is False
