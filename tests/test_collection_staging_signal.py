"""TDD (D2 brick 1): Collection / data-staging signal from filesystem_timeline_fact.

The live Acme run compiled 25,715 MFT rows into filesystem_timeline_fact, but
_score_fact had NO branch for that type -> the whole filesystem timeline scored
as context-only noise. This adds a dataset-agnostic Collection/staging signal
(MITRE TA0009 Collection / T1560 Archive Collected Data): an archive/container
file located under a user-writable staging path.

Dataset-agnostic: reuses the existing _SUSPICIOUS_STAGING_RE (no new path list)
plus a universal archive-extension set (like the existing _EXEC_EXT_RE). Keys on
NO host/user/IP/case literal -- swap-test holds on any image.

Bounded by design: a lone filesystem_timeline signal is single-source/single-
type, so it stays review_worthy and never auto-promotes (validation_ready needs
multi-source + multi-fact-type + score>=60). Surfacing it as a confirmed finding
is a separate, gated vertical (malicious_semantics + disposition).
"""
from sift_sentinel.analysis.candidate_observations import _score_fact, _candidate_type


def _fs(path):
    return {"fact_type": "filesystem_timeline_fact", "path": path,
            "fields": {"path": path}}


def test_archive_in_user_staging_emits_collection_signal():
    score, signals, _ = _score_fact(
        _fs(r"C:\Users\someuser\AppData\Local\Temp\export.zip"))
    assert "archive_in_staging_path" in signals
    assert score >= 40
    assert _candidate_type(set(signals)) == "data_collection_staging"


def test_archive_outside_staging_emits_nothing():
    _, signals, _ = _score_fact(_fs(r"C:\Backups\nightly\archive.7z"))
    assert "archive_in_staging_path" not in signals


def test_nonarchive_in_staging_emits_nothing():
    _, signals, _ = _score_fact(
        _fs(r"C:\Users\someuser\AppData\Local\Temp\readme.txt"))
    assert "archive_in_staging_path" not in signals


def test_collection_signal_is_dataset_agnostic_for_any_user():
    # Same structural pattern, different (arbitrary) user -> still fires.
    _, signals, _ = _score_fact(
        _fs(r"C:\Users\anybody\AppData\Local\Temp\bundle.rar"))
    assert "archive_in_staging_path" in signals
