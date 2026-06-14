"""Regression: registry-persistence baseline suppression (dataset-agnostic).

Unmodified Windows defaults must NOT raise high_risk_persistence; any modification
(comma-append hijack, staging path, LOLBIN/encoded payload, bare-exe replacement)
must still fire. Keys on OS invariants + structure only -- no case data.
"""
from sift_sentinel.analysis.candidate_observations import (
    _registry_value_is_baseline as base, _score_fact,
)

DEFAULTS = ["explorer.exe", r"C:\Windows\system32\userinit.exe,",
            r"%windir%\system32\SecurityHealthSystray.exe",
            r"C:\Windows\System32\userinit.exe"]
MODS = [r"explorer.exe,C:\Temp\evil.exe",
        r"C:\Windows\system32\userinit.exe,C:\Users\x\AppData\Local\Temp\e.exe",
        r"C:\Users\Public\beacon.exe", r"powershell -enc ZQB2AGkA", "evil.exe",
        r"C:\ProgramData\staging\impl.exe"]

def test_defaults_are_baseline():
    for v in DEFAULTS:
        assert base(v) is True, f"default not recognized as baseline: {v!r}"

def test_modifications_are_not_baseline():
    for v in MODS:
        assert base(v) is False, f"modification treated as baseline: {v!r}"

def test_score_fact_gates_default_not_hijack():
    loc = r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    def hrp(vd):
        f = {"fact_type": "registry_persistence_fact", "value_name": "Shell",
             "value_data": vd, "key": loc, "key_path": loc, "registry_key": loc,
             "path": loc, "raw": loc + " Shell"}
        _, signals, supp = _score_fact(f)
        return ("high_risk_persistence" in signals), supp
    fired_evil, _ = hrp(r"explorer.exe,C:\Users\Public\evil.exe")
    fired_def, supp = hrp("explorer.exe")
    assert fired_evil, "hijack did not fire high_risk_persistence"
    assert not fired_def, f"default still flagged; supp={supp}"
    assert "registry_persistence_default_value" in supp
