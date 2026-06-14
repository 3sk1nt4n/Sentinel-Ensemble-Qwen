"""SafeBoot AlternateShell persistence must NOT fire on the OS default value,
and must NOT fire when the only readable datum is the registry KEY PATH (a
model-emitted path claim) rather than the value-data. Fail-closed: deviation
from the default can only be asserted when the actual value-data is visible.

Universal: keyed on the OS-defined default + the structural fact that a key
path is not value-data; no case literal. Regression guard for the F034 live FP
(AlternateShell=cmd.exe confirmed as persistence because the matcher read the
claim's `value` field, which held the key path, not the value-data).
"""
from sift_sentinel.analysis.malicious_semantics import (
    has_malicious_semantic,
    match_safeboot_alternateshell_persistence as fire,
)


# ── declared-signal verification (the F034 confirmed-bucket FP) ──────────
def _reg_fact(value_data):
    return {
        "fact_type": "registry_persistence_fact",
        "registry_path": "HKLM\\SYSTEM\\ControlSet001\\Control\\SafeBoot",
        "value_name": "AlternateShell",
        "value_data": value_data,
        "persistence_type": "safeboot",
    }


def test_declared_safeboot_signal_dropped_when_value_is_default():
    # F034 shape: model DECLARES the conclusive persistence signal, but the
    # only real evidence (a candidate fact) has value_data=cmd.exe (default),
    # so the matcher does NOT fire -> the declaration must be dropped.
    finding = {
        "finding_id": "F034",
        "title": "Registry persistence via SafeBoot AlternateShell",
        "malicious_semantic_signals": ["safeboot_alternateshell_persistence"],
        "claims": [_reg_fact("cmd.exe")],
    }
    has_sem, sigs = has_malicious_semantic(finding)
    assert "safeboot_alternateshell_persistence" not in sigs
    assert has_sem is False


def test_declared_safeboot_signal_kept_when_value_is_non_default():
    finding = {
        "finding_id": "Fx",
        "title": "SafeBoot hijack",
        "malicious_semantic_signals": ["safeboot_alternateshell_persistence"],
        "claims": [_reg_fact("evil.exe")],
    }
    has_sem, sigs = has_malicious_semantic(finding)
    assert "safeboot_alternateshell_persistence" in sigs
    assert has_sem is True


def test_declared_safeboot_no_facts_preserves_declaration():
    # No candidate facts at all -> cannot verify -> keep prior behavior
    # (trust the declaration) so unrelated callers do not regress.
    finding = {
        "finding_id": "Fy",
        "title": "SafeBoot",
        "malicious_semantic_signals": ["safeboot_alternateshell_persistence"],
    }
    has_sem, sigs = has_malicious_semantic(finding)
    assert "safeboot_alternateshell_persistence" in sigs


def test_other_declared_signals_unaffected():
    # A non-conclusive declared signal is still trusted by name (no regression).
    finding = {
        "finding_id": "Fz",
        "title": "egress",
        "malicious_semantic_signals": ["srum_egress_outlier"],
        "claims": [{"type": "path", "value": "x"}],
    }
    has_sem, sigs = has_malicious_semantic(finding)
    assert "srum_egress_outlier" in sigs


def test_default_cmd_exe_does_not_fire():
    fact = {
        "fact_type": "registry_persistence_fact",
        "registry_path": "HKLM\\System\\ControlSet001\\Control\\SafeBoot",
        "value_name": "AlternateShell",
        "value_data": "cmd.exe",
    }
    assert fire(fact) is False


def test_non_default_shell_fires():
    fact = {
        "fact_type": "registry_persistence_fact",
        "registry_path": "HKLM\\System\\ControlSet001\\Control\\SafeBoot",
        "value_name": "AlternateShell",
        "value_data": "evil.exe",
    }
    assert fire(fact) is True


def test_path_only_claim_does_not_fire():
    # The F034 shape: a model claim whose `value` is the KEY PATH, with no
    # value-data. Must NOT fire -- the value is unknown, so deviation from the
    # default cannot be asserted (fail-closed).
    claim = {
        "type": "path",
        "value": "HKLM\\System\\ControlSet001\\Control\\SafeBoot\\AlternateShell",
    }
    assert fire(claim) is False


def test_path_only_claim_value_data_field_still_works():
    # A claim that DOES carry the value-data under value_data still adjudicates.
    claim = {
        "type": "path",
        "value": "HKLM\\System\\ControlSet001\\Control\\SafeBoot\\AlternateShell",
        "value_data": "cmd.exe",
    }
    assert fire(claim) is False


def test_missing_value_data_fails_closed():
    fact = {
        "fact_type": "registry_persistence_fact",
        "registry_path": "HKLM\\System\\ControlSet001\\Control\\SafeBoot\\AlternateShell",
        "value_name": "AlternateShell",
    }
    assert fire(fact) is False


def test_unrelated_key_does_not_fire():
    fact = {
        "fact_type": "registry_persistence_fact",
        "registry_path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "SecurityHealth",
        "value_data": "C:\\Windows\\System32\\SecurityHealthSystray.exe",
    }
    assert fire(fact) is False
