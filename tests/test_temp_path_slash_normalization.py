"""match_executes_from_temp_path normalizes slashes (like lnk/jumplist) so it matches real
Windows staging dirs on forward-slash / mount-read paths and does NOT false-match the host
evidence-mount prefix. Dataset-agnostic: path shapes only, no case IOCs."""
from sift_sentinel.analysis.malicious_semantics import match_executes_from_temp_path as m
def _f(p): return {"fact_type":"file_execution_fact","path":p,"normalized_path":p.lower()}
MNT="/tmp/sift-isolated-mount-acme-20260531-171806-023923434/ntfs/"
def test_mount_read_prefetch_does_not_fire():
    assert m(_f(MNT+"Windows/Prefetch/TEAMS.EXE-AC6AB058.pf")) is False
def test_mount_read_system32_does_not_fire():
    assert m(_f(MNT+"Windows/System32/svchost.exe")) is False
def test_real_windows_temp_on_mount_still_fires():
    assert m(_f(MNT+"Windows/Temp/evil.exe")) is True
    assert m(_f(MNT+"Users/Public/payload.exe")) is True
def test_native_backslash_staging_still_fires():
    assert m(_f("\\Windows\\Temp\\stager.exe")) is True
    assert m(_f("C:\\Users\\x\\AppData\\Local\\Temp\\a.exe")) is True
def test_canonical_appdata_app_does_not_fire():
    assert m(_f("C:\\Users\\bobby\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe")) is False
