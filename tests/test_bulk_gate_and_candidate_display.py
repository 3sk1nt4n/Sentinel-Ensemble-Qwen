"""Two operator-facing fixes:

1. bulk_extractor auto-runs ONLY on a memory-only case (no disk image/mount);
   when a disk is present its full-image carve is redundant cost and is dropped.
2. the candidate-observation line shows returned(total) so the return cap is
   visible -- e.g. "1000(1137) capped".

run_pipeline.py is a top-level script, so the wiring is asserted structurally
(text), the candidate field via the importable builder. Synthetic only.
"""
from __future__ import annotations

from pathlib import Path

from sift_sentinel.analysis.candidate_observations import (
    build_candidate_observations,
)

_SRC = (Path(__file__).resolve().parent.parent / "run_pipeline.py").read_text()


# ── candidate total (pre-cap reality) ────────────────────────────────────

def test_candidate_dict_exposes_total_candidate_count():
    out = build_candidate_observations({"typed_facts": {}, "indexes": {}})
    assert "total_candidate_count" in out
    assert isinstance(out["total_candidate_count"], int)
    # with no facts, returned == total == 0
    assert out["total_candidate_count"] == out["returned_candidate_count"]


def test_candidate_total_matches_ceiling():
    out = build_candidate_observations({"typed_facts": {}, "indexes": {}})
    assert out["total_candidate_count"] == \
        out["validation_ready_ceiling"]["total_candidates"]


def test_display_format_shows_bracket_when_capped():
    # the print renders returned(total) capped when total > returned
    assert '%d(%d) capped' in _SRC
    assert "total_candidate_count" in _SRC


# ── bulk_extractor memory-only gate ──────────────────────────────────────

def test_bulk_memory_only_predicate_present():
    assert ("_sift_bulk_memory_only = bool(IMAGE_PATH) and not "
            "(bool(DISK_PATH) or bool(_args.disk_mount))") in _SRC
    assert "_sift_bulk_auto = _sift_bulk_memory_only" in _SRC


def test_bulk_dropped_when_disk_present():
    assert "dropped run_bulk_extractor (disk present" in _SRC
    # the drop respects an explicit opt-in
    assert "not _sift_bulk_optin and (bool(DISK_PATH) or bool(_args.disk_mount))" in _SRC


def test_bulk_optin_still_overrides():
    assert 'os.getenv("SIFT_RUN_BULK_EXTRACTOR"' in _SRC
    assert "_sift_bulk_optin or _sift_bulk_auto" in _SRC
