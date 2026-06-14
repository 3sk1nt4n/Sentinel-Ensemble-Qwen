"""Cache provenance: load_cached must reject hits from other evidence images.

Every cache write pairs the data file with a ``<cache>.meta.json`` recording
the evidence SHA256.  A load that supplies a hash must match, or the cache
is treated as a miss (returns ``None`` + logs "Cache rejected").
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from sift_sentinel.tools.common import (
    _meta_path,
    load_cached,
    write_cached,
)


# Two distinct evidence hashes used throughout the tests.
HASH_A = "a" * 64
HASH_B = "b" * 64


class TestWriteCached:
    def test_writes_cache_and_meta(self, tmp_path: Path):
        cache = tmp_path / "vol_pstree.json"
        records = [{"PID": 4, "ImageFileName": "System"}]
        write_cached(cache, records,
                     evidence_sha256=HASH_A, tool_name="vol_pstree")

        assert cache.exists()
        assert _meta_path(cache).exists()

        meta = json.loads(_meta_path(cache).read_text())
        assert meta["evidence_sha256"] == HASH_A
        assert meta["tool"] == "vol_pstree"
        assert meta["records_count"] == 1
        assert "timestamp" in meta

    def test_requires_non_empty_hash(self, tmp_path: Path):
        with pytest.raises(ValueError, match="evidence_sha256"):
            write_cached(
                tmp_path / "x.json", [],
                evidence_sha256="", tool_name="vol_pstree",
            )

    def test_dict_output_records_count(self, tmp_path: Path):
        cache = tmp_path / "get_amcache.json"
        data = {"a": 1, "b": 2, "c": 3}
        write_cached(cache, data,
                     evidence_sha256=HASH_A, tool_name="get_amcache")
        meta = json.loads(_meta_path(cache).read_text())
        assert meta["records_count"] == 3


class TestLoadCached:
    def test_roundtrip_matching_hash(self, tmp_path: Path):
        cache = tmp_path / "vol_pstree.json"
        records = [{"PID": 4, "ImageFileName": "System"}]
        write_cached(cache, records,
                     evidence_sha256=HASH_A, tool_name="vol_pstree")

        result = load_cached(cache, evidence_sha256=HASH_A)
        assert result == records

    def test_cache_rejects_wrong_evidence(self, tmp_path: Path, caplog):
        """Write cache for evidence A, load with evidence B -> miss."""
        cache = tmp_path / "vol_netscan.json"
        write_cached(cache, [{"PID": 1204}],
                     evidence_sha256=HASH_A, tool_name="vol_netscan")

        with caplog.at_level(logging.WARNING,
                              logger="sift_sentinel.tools.common"):
            result = load_cached(cache, evidence_sha256=HASH_B)

        assert result is None
        assert any("Cache rejected" in rec.message for rec in caplog.records)

    def test_missing_meta_rejected(self, tmp_path: Path, caplog):
        """Cache file without .meta.json cannot be trusted."""
        cache = tmp_path / "legacy.json"
        cache.write_text(json.dumps([{"PID": 4}]))
        # No meta sidecar written -- simulates a legacy/untrusted file.

        with caplog.at_level(logging.WARNING,
                              logger="sift_sentinel.tools.common"):
            result = load_cached(cache, evidence_sha256=HASH_A)

        assert result is None
        assert any("Cache rejected" in rec.message for rec in caplog.records)

    def test_no_hash_skips_check(self, tmp_path: Path):
        """When no evidence_sha256 is passed, meta check is skipped."""
        cache = tmp_path / "legacy.json"
        payload = [{"PID": 4}]
        cache.write_text(json.dumps(payload))

        result = load_cached(cache, evidence_sha256=None)
        assert result == payload

    def test_missing_cache_returns_none(self, tmp_path: Path):
        result = load_cached(tmp_path / "does_not_exist.json",
                              evidence_sha256=HASH_A)
        assert result is None

    def test_corrupt_meta_rejected(self, tmp_path: Path, caplog):
        cache = tmp_path / "vol_pstree.json"
        cache.write_text(json.dumps([]))
        _meta_path(cache).write_text("{not valid json")

        with caplog.at_level(logging.WARNING,
                              logger="sift_sentinel.tools.common"):
            result = load_cached(cache, evidence_sha256=HASH_A)

        assert result is None
        assert any("Cache rejected" in rec.message for rec in caplog.records)
