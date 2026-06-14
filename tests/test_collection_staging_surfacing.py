"""TDD (D2 surfacing vertical / option A): a Collection candidate -- an archive
staged under a user-writable transient path -- is registered as a malicious
SEMANTIC, so disposition's corroboration-floor sees a NON-weak signal and routes
the finding to suspicious_needs_review instead of filing it benign.

Proof is at the semantic-registry + floor-set level (the routing itself is the
verified `verdict != malicious and not strong and _floor_weak_only -> BENIGN`
gate at disposition.py:1063; a registered, non-weak semantic makes
`_floor_weak_only` False, so the finding escapes to BUCKET_SUSPICIOUS at 1068).

Dataset-agnostic: structural (archive extension + transient-path token), no
threshold, no host/user/path/case literal.
"""
from sift_sentinel.analysis import malicious_semantics as ms
from sift_sentinel.analysis import disposition as disp


def _fs(path):
    return {"fact_type": "filesystem_timeline_fact", "path": path,
            "fields": {"path": path}}


def test_matcher_fires_on_archive_in_user_temp():
    assert ms.match_archive_in_staging_path(
        _fs(r"C:\Users\someuser\AppData\Local\Temp\export.zip")) is True


def test_matcher_ignores_archive_outside_staging():
    assert ms.match_archive_in_staging_path(_fs(r"C:\Backups\archive.7z")) is False


def test_matcher_ignores_nonarchive_in_staging():
    assert ms.match_archive_in_staging_path(
        _fs(r"C:\Users\someuser\AppData\Local\Temp\readme.txt")) is False


def test_signal_registered_and_not_weak_alone():
    assert "archive_in_staging_path" in ms.MALICIOUS_SEMANTIC_SIGNALS
    # Must NOT be weak-alone / disk-history, else the benign floor eats it.
    assert "archive_in_staging_path" not in disp._WEAK_ALONE_SEMANTIC_SIGNALS
    assert "archive_in_staging_path" not in disp._DISK_HISTORY_SEMANTIC_SIGNALS


def test_has_malicious_semantic_recognizes_declared_signal():
    has, sigs = ms.has_malicious_semantic(
        {"malicious_semantic_signals": ["archive_in_staging_path"]},
        evidence_db=None)
    assert has is True
    assert "archive_in_staging_path" in sigs
