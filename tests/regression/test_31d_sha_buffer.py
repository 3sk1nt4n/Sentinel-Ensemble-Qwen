"""Slot 31D-SHA-BUFFER regression tests.

Pins:
  - sha256_fingerprint digest is byte-identical to a reference
    hashlib.sha256 of the same bytes regardless of buffer size
    (SIFT_SHA256_BUFFER_MIB in {1, 16, 64});
  - non-power-of-two / non-buffer-aligned file sizes hash identically
    across buffer sizes (chunk-boundary safety);
  - the buffer env var is clamped: "0" -> 1 MiB, "9999" -> 256 MiB,
    invalid -> default 16 MiB. None of these crash or change the
    digest.

Cheap, no-live, no subprocess. Hashes are computed by the in-process
sha256_fingerprint against synthetic byte streams.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from sift_sentinel.coordinator import sha256_fingerprint


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ref_digest(payload: bytes) -> str:
    """Reference digest -- the single source of truth for these tests."""
    return hashlib.sha256(payload).hexdigest()


def _write(tmp_path: Path, name: str, payload: bytes) -> Path:
    fp = tmp_path / name
    fp.write_bytes(payload)
    return fp


def _run_with_buffer(
    monkeypatch, path: Path, mib: str | None,
) -> str:
    """Invoke sha256_fingerprint with SIFT_SHA256_BUFFER_MIB set/unset."""
    if mib is None:
        monkeypatch.delenv("SIFT_SHA256_BUFFER_MIB", raising=False)
    else:
        monkeypatch.setenv("SIFT_SHA256_BUFFER_MIB", mib)
    result = sha256_fingerprint([str(path)])
    return result[str(path)]


# ---------------------------------------------------------------------------
# Test 1: digest is identical across SIFT_SHA256_BUFFER_MIB in {1, 16, 64}.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "size",
    [
        4 * 1024,            # smaller than 1 MiB buffer
        1024 * 1024,         # exactly 1 MiB
        2 * 1024 * 1024 + 1, # crosses a 1-MiB boundary by one byte
    ],
)
def test_digest_identical_across_buffer_sizes(
    monkeypatch, tmp_path: Path, size: int,
) -> None:
    # Deterministic non-trivial payload (cycle of byte values).
    payload = bytes(((i * 31 + 7) & 0xFF) for i in range(size))
    fp = _write(tmp_path, f"payload_{size}.bin", payload)
    ref = _ref_digest(payload)

    digests = {
        mib: _run_with_buffer(monkeypatch, fp, mib)
        for mib in ("1", "16", "64")
    }

    assert all(d == ref for d in digests.values()), (
        f"sha256_fingerprint digest must match hashlib.sha256 reference "
        f"across buffer sizes.\n  ref={ref}\n  got={digests}"
    )
    # And all buffer sizes must agree with each other.
    assert len(set(digests.values())) == 1, digests


# ---------------------------------------------------------------------------
# Test 2: non-aligned size (5_000_003 bytes) -- identical across buffers.
# ---------------------------------------------------------------------------


def test_non_aligned_size_identical_across_buffers(
    monkeypatch, tmp_path: Path,
) -> None:
    size = 5_000_003  # deliberately not a multiple of any chunk boundary
    # Use a mix of byte values; avoid all-zero (more catches bit drops).
    payload = bytes(((i ^ 0xA5) * 13 + i) & 0xFF for i in range(size))
    fp = _write(tmp_path, "nonaligned.bin", payload)
    ref = _ref_digest(payload)

    digests = {
        mib: _run_with_buffer(monkeypatch, fp, mib)
        for mib in ("1", "16", "64")
    }

    for mib, d in digests.items():
        assert d == ref, (
            f"Non-aligned 5_000_003-byte digest differs at "
            f"SIFT_SHA256_BUFFER_MIB={mib}: got {d}, expected {ref}"
        )


# ---------------------------------------------------------------------------
# Test 3: clamp -- "0" and "9999" do not crash and return the same digest.
# ---------------------------------------------------------------------------


def test_buffer_env_clamps_and_preserves_digest(
    monkeypatch, tmp_path: Path,
) -> None:
    size = 257_001  # arbitrary mid-sized, non-aligned payload
    payload = bytes(((i * 17) ^ (i >> 3)) & 0xFF for i in range(size))
    fp = _write(tmp_path, "clamp.bin", payload)
    ref = _ref_digest(payload)

    # "0" -> clamped to 1 MiB minimum.
    d_low = _run_with_buffer(monkeypatch, fp, "0")
    # "9999" -> clamped to 256 MiB maximum.
    d_high = _run_with_buffer(monkeypatch, fp, "9999")
    # Default (env unset).
    d_default = _run_with_buffer(monkeypatch, fp, None)
    # Invalid value -> falls back to the 16 MiB default without crashing.
    d_invalid = _run_with_buffer(monkeypatch, fp, "not-a-number")

    assert d_low == ref, f"clamp-low digest drift: {d_low} != {ref}"
    assert d_high == ref, f"clamp-high digest drift: {d_high} != {ref}"
    assert d_default == ref, f"default digest drift: {d_default} != {ref}"
    assert d_invalid == ref, f"invalid-env digest drift: {d_invalid} != {ref}"


# ---------------------------------------------------------------------------
# Bonus: an empty file hashes to the canonical SHA256 of zero bytes,
# identically across all buffer sizes. Cheap belt-and-suspenders for
# the "no skip / no sample" rule -- proves a zero-byte input is not
# accidentally short-circuited by the buffer-loop logic.
# ---------------------------------------------------------------------------


def test_empty_file_hashes_to_canonical_zero_byte_sha256(
    monkeypatch, tmp_path: Path,
) -> None:
    expected = hashlib.sha256(b"").hexdigest()
    fp = _write(tmp_path, "zero_bytes.bin", b"")
    for mib in ("1", "16", "64"):
        d = _run_with_buffer(monkeypatch, fp, mib)
        assert d == expected, (
            f"Zero-byte file digest drift at "
            f"SIFT_SHA256_BUFFER_MIB={mib}: got {d}, expected {expected}"
        )
