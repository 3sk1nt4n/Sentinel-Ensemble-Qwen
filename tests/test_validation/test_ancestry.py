import pytest
from sift_sentinel.validation.ancestry import check_ancestry

def test_svchost_clean():
    tree = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 50, "PPID": 4, "ImageFileName": "smss.exe"},
        {"PID": 80, "PPID": 50, "ImageFileName": "wininit.exe"},
        {"PID": 100, "PPID": 80, "ImageFileName": "services.exe"},
        {"PID": 200, "PPID": 100, "ImageFileName": "svchost.exe"},
    ]
    assert len(check_ancestry(tree)) == 0

def test_svchost_violation():
    tree = [
        {"PID": 100, "PPID": 4, "ImageFileName": "cmd.exe"},
        {"PID": 200, "PPID": 100, "ImageFileName": "svchost.exe"}
    ]
    res = check_ancestry(tree)
    assert len(res) == 1
    assert res[0]["actual_parent"] == "cmd.exe"

def test_lsass_clean():
    tree = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 50, "PPID": 4, "ImageFileName": "smss.exe"},
        {"PID": 100, "PPID": 50, "ImageFileName": "wininit.exe"},
        {"PID": 200, "PPID": 100, "ImageFileName": "lsass.exe"},
    ]
    assert len(check_ancestry(tree)) == 0

def test_lsass_violation():
    tree = [
        {"PID": 100, "PPID": 4, "ImageFileName": "explorer.exe"},
        {"PID": 200, "PPID": 100, "ImageFileName": "lsass.exe"}
    ]
    res = check_ancestry(tree)
    assert len(res) == 1

def test_csrss_clean():
    tree = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 100, "PPID": 4, "ImageFileName": "smss.exe"},
        {"PID": 200, "PPID": 100, "ImageFileName": "csrss.exe"},
    ]
    assert len(check_ancestry(tree)) == 0

def test_unknown_passes():
    tree = [
        {"PID": 100, "PPID": 4, "ImageFileName": "explorer.exe"},
        {"PID": 200, "PPID": 100, "ImageFileName": "unknown_malware.exe"}
    ]
    assert len(check_ancestry(tree)) == 0

def test_mixed_tree():
    tree = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 5, "PPID": 4, "ImageFileName": "smss.exe"},
        {"PID": 8, "PPID": 5, "ImageFileName": "wininit.exe"},
        {"PID": 10, "PPID": 8, "ImageFileName": "services.exe"},
        {"PID": 20, "PPID": 10, "ImageFileName": "svchost.exe"},
        {"PID": 30, "PPID": 20, "ImageFileName": "lsass.exe"},
    ]
    res = check_ancestry(tree)
    assert len(res) == 1
    assert res[0]["process"] == "lsass.exe"

def test_smss_child_of_smss_clean():
    tree = [
        {"PID": 100, "PPID": 4, "ImageFileName": "smss.exe"},
        {"PID": 200, "PPID": 100, "ImageFileName": "smss.exe"}
    ]
    assert len(check_ancestry(tree)) == 0

def test_empty_tree():
    assert len(check_ancestry([])) == 0
