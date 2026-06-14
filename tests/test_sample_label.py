"""Summary 'Sample' label: the COMMON NAME of the memory+disk pair (shared file stem,
trimmed at the role token) + each artefact's size -- never the parent bucket folder.
Universal: derived from the given file names/sizes, no case literal.
"""
import os

from sift_sentinel.reporting.sample_label import (
    sample_label, sample_name, human_size,
)


def test_common_stem_from_pair_not_folder(tmp_path):
    # the live failure: parent folder 'all-cases' was used instead of the sample name
    evd = tmp_path / "evidence" / "all-cases" / "alice-case"
    evd.mkdir(parents=True)
    mem = evd / "win7-64-alice-memory.img"
    disk = evd / "win7-64-alice-cdrive.E01"
    mem.write_bytes(b"x" * 2048)
    disk.write_bytes(b"y" * 4096)
    assert sample_name(str(mem), str(disk)) == "win7-64-alice"
    label = sample_label({}, str(mem), str(disk))
    assert label.startswith("win7-64-alice  (")
    assert "all-cases" not in label
    assert "memory" in label and "disk" in label


def test_label_carries_sizes(tmp_path):
    mem = tmp_path / "host-a-memory.raw"
    disk = tmp_path / "host-a-disk.e01"
    mem.write_bytes(b"x" * (3 * 1024 * 1024))      # 3 MB
    disk.write_bytes(b"y" * (10 * 1024 * 1024))    # 10 MB
    label = sample_label({}, str(mem), str(disk))
    assert "memory 3 MB" in label
    assert "disk 10 MB" in label
    assert label.startswith("host-a  (")


def test_single_memory_only(tmp_path):
    mem = tmp_path / "case7-memory.img"
    mem.write_bytes(b"x" * 1024)
    assert sample_name(str(mem)) == "case7"
    label = sample_label({}, str(mem), None)
    assert "disk" not in label
    assert "memory" in label


def test_sizeless_paths_fall_back_to_memory_plus_disk():
    # synthetic paths (no real file) -> sizes omitted, the old 'memory + disk' shape kept
    label = sample_label({}, "/evidence/x/foo-memory.img", "/evidence/x/foo-disk.e01")
    assert "memory + disk" in label


def test_explicit_summary_sample_wins():
    assert sample_label({"sample": "MY-CASE"}, "/e/a-memory.img", "/e/a-disk.e01").startswith("MY-CASE")


def test_folder_fallback_skips_generic_buckets():
    # no usable file stem -> use the file's own dir, but never a generic bucket name
    assert sample_name("/cases/evidence/all-cases/host9-case/memory.img") == "host9"


def test_human_size_formatting():
    assert human_size(0) == ""
    assert human_size(512) == "512 B"
    assert human_size(3 * 1024 ** 3) == "3 GB"
    assert human_size(int(3.4 * 1024 ** 3)) == "3.4 GB"
    assert human_size(16 * 1024 ** 3) == "16 GB"
