"""Step 1-2-3 speed fix: single full SHA pass + big-read hashing.

Dataset-agnostic:
- no case names, PIDs, users, IPs, or expected answers
- no caching old fingerprints
- precomputed_hashes is same-run handoff only
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def test_step_02_uses_precomputed_hashes_without_rehashing(monkeypatch, tmp_path):
    import sift_sentinel.coordinator as c

    def forbidden(*args, **kwargs):
        raise AssertionError("sha256_fingerprint must not be called when precomputed_hashes is supplied")

    monkeypatch.setattr(c, "sha256_fingerprint", forbidden)

    expected = {"/synthetic/evidence.bin": "a" * 64}
    out = c.step_02_fingerprint(
        ["/synthetic/evidence.bin"],
        tmp_path,
        precomputed_hashes=expected,
    )

    assert out == expected
    txt = (tmp_path / "sha256_pre.txt").read_text(errors="replace")
    assert "/synthetic/evidence.bin" in txt
    assert "a" * 64 in txt


def test_step_02_without_precomputed_hashes_still_hashes_normally(tmp_path):
    from sift_sentinel.coordinator import step_02_fingerprint

    f = tmp_path / "evidence.bin"
    payload = b"A" * 8192 + b"tail"
    f.write_bytes(payload)

    expected = hashlib.sha256(payload).hexdigest()
    assert step_02_fingerprint([str(f)], tmp_path) == {str(f): expected}


def test_bigread_sha_matches_hashlib(tmp_path):
    import sift_sentinel.coordinator as c

    f = tmp_path / "large-ish.bin"
    payload = b"A" * (3 * 1024 * 1024) + b"B" * 17
    f.write_bytes(payload)

    assert c._SHA256_READ_CHUNK_BYTES >= 1024 * 1024
    assert c._sha256_file_full_read(f) == hashlib.sha256(payload).hexdigest()
    assert c.sha256_fingerprint([str(f)]) == {
        str(f): hashlib.sha256(payload).hexdigest()
    }


def test_run_pipeline_step1_to_step3_has_single_sha_handoff():
    text = Path("run_pipeline.py").read_text(errors="replace")
    start = text.find("# STEP 1")
    end = text.find("# STEP 3")
    assert start >= 0 and end > start
    window = text[start:end]

    assert window.count("sha256_fingerprint(") <= 1
    assert window.count("step_02_fingerprint(") <= 1
    assert "precomputed_hashes=_pre_hashes" in window

    step2_log_pos = window.find("Step 2: SHA256 fingerprinting evidence files")
    hash_pos = window.find("sha256_fingerprint(")
    assert step2_log_pos >= 0
    assert hash_pos >= 0
    assert step2_log_pos < hash_pos


def test_no_old_hash_artifact_is_loaded_to_skip_hashing():
    text = Path("run_pipeline.py").read_text(errors="replace")
    forbidden = [
        'read_state(STATE_DIR, "sha256_pre',
        "read_state(STATE_DIR, 'sha256_pre",
        'read_state(STATE_DIR, "sha256_post',
        "read_state(STATE_DIR, 'sha256_post",
        'open(STATE_DIR / "sha256_pre',
        "open(STATE_DIR / 'sha256_pre",
        'open(STATE_DIR / "sha256_post',
        "open(STATE_DIR / 'sha256_post",
    ]
    for bad in forbidden:
        assert bad not in text
