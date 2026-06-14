"""Ensemble dedup: file-based findings (no pid/process entity) must collapse on a
NORMALIZED file path, not on per-member title prose.

Live run: one insider sdelete execution surfaced as 4 separate findings (F010/
F019/F025/F053) -- same file, three case/separator/drive forms
(Users/.../sdelete.exe, C:\\Users\\...\\sdelete.exe, users/.../sdelete.exe) and
four different member-written titles. With no pid/process entity they fell to the
artifact+title fallback -> distinct fingerprints -> never merged. Keying path-only
findings on the normalized path collapses them. Universal: pure path
normalization, no case data; pid/process/ip/hash findings are untouched.
"""
from sift_sentinel.ensemble import _fingerprint, merge_ensemble_findings


def test_same_file_different_form_same_fingerprint():
    f1 = {"claims": [{"type": "path", "value": "Users/bobby/downloads/sdelete/sdelete.exe"}],
          "title": "Anti-forensics tool sdelete execution detected"}
    f2 = {"claims": [{"type": "path", "value": r"C:\Users\bobby\Downloads\sdelete\sdelete.exe"}],
          "title": "sdelete.exe execution in user Downloads"}
    f3 = {"claims": [{"type": "path", "value": "users/bobby/downloads/sdelete/sdelete.exe"}],
          "title": "Anti-forensics tool detected: sdelete.exe (attacker staging)"}
    assert _fingerprint(f1) == _fingerprint(f2) == _fingerprint(f3)


def test_device_volume_prefix_normalizes():
    f1 = {"claims": [{"type": "path", "value": "/Device/HarddiskVolume3/Program Files/x.exe"}]}
    f2 = {"claims": [{"type": "path", "value": "Program Files/x.exe"}]}
    assert _fingerprint(f1) == _fingerprint(f2)


def test_pid_findings_unaffected_by_path_no_regression():
    # A finding carrying a pid entity keys on the pid; a path claim on it is
    # ignored so it still dedupes against the same pid from another member.
    a = {"claims": [{"pid": 8312, "process": "SearchApp.exe"}], "title": "inj A"}
    b = {"claims": [{"pid": 8312, "process": "SearchApp.exe", "path": r"C:\X\y.exe"}],
         "title": "inj B (different prose)"}
    assert _fingerprint(a) == _fingerprint(b)


def test_different_files_do_not_collapse():
    f1 = {"claims": [{"type": "path", "value": "users/bobby/downloads/sdelete.exe"}]}
    f2 = {"claims": [{"type": "path", "value": "users/bobby/downloads/eraser.exe"}]}
    assert _fingerprint(f1) != _fingerprint(f2)


def test_empty_finding_still_unique():
    # No entity, no path, no artifact/title -> unique key (never collapses).
    assert _fingerprint({}) != _fingerprint({})


def test_merge_collapses_one_insider_sdelete_into_single_finding():
    per_model = {
        "m1": {"findings": [
            {"claims": [{"type": "path", "value": "Users/bobby/downloads/sdelete/sdelete.exe"}],
             "title": "Anti-forensics tool sdelete execution detected"}]},
        "m2": {"findings": [
            {"claims": [{"type": "path", "value": r"C:\Users\bobby\Downloads\sdelete\sdelete.exe"}],
             "title": "sdelete.exe execution in user Downloads"}]},
        "m3": {"findings": [
            {"claims": [{"type": "path", "value": "users/bobby/downloads/sdelete/sdelete.exe"}],
             "title": "Anti-forensics tool execution: sdelete in user directory"}]},
    }
    merged, _ = merge_ensemble_findings(per_model)
    assert len(merged) == 1, [m.get("title") for m in merged]
    assert sorted(merged[0]["discovered_by"]) == ["m1", "m2", "m3"]
