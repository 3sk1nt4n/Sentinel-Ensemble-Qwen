"""FIX D (#3): run_memprocfs is FLOORED on a memory-only case (binary-gated).

run_memprocfs (MemProcFS FindEvil) is high-value memory-anomaly coverage but is
opt-in by default (removed from selection unless SIFT_ALLOW_MEMPROCFS) because it
is slow and needs the MemProcFS binary. On a MEMORY-ONLY case it is exactly the
right tool -- its FindEvil family is now compiled (memprocfs_indicator_fact) and
scored as a candidate. Floor it there, but ONLY when the binary is actually
present, so on a judge box without MemProcFS it is a clean no-op (never an error
envelope, never a phantom selection). Paired/disk runs are unchanged.

Universal: keyed on evidence-channel presence + binary availability, no case data.
Kill switch SIFT_MEMPROCFS_MEMONLY=0.
"""
import pathlib

from sift_sentinel import coordinator as C


def test_helper_exists():
    assert hasattr(C, "should_floor_memprocfs_memonly")


def test_memory_only_with_binary_floors():
    assert C.should_floor_memprocfs_memonly(
        has_memory=True, has_disk=False, binary_present=True, env={}
    ) is True


def test_memory_only_without_binary_does_not_floor():
    # judge box without MemProcFS -> clean no-op, not an error
    assert C.should_floor_memprocfs_memonly(
        has_memory=True, has_disk=False, binary_present=False, env={}
    ) is False


def test_paired_run_does_not_floor():
    assert C.should_floor_memprocfs_memonly(
        has_memory=True, has_disk=True, binary_present=True, env={}
    ) is False


def test_disk_only_does_not_floor():
    assert C.should_floor_memprocfs_memonly(
        has_memory=False, has_disk=True, binary_present=True, env={}
    ) is False


def test_kill_switch_disables_floor():
    assert C.should_floor_memprocfs_memonly(
        has_memory=True, has_disk=False, binary_present=True,
        env={"SIFT_MEMPROCFS_MEMONLY": "0"},
    ) is False


def test_run_pipeline_wires_the_memonly_memprocfs_floor():
    rp = (pathlib.Path(__file__).resolve().parents[1] / "run_pipeline.py").read_text()
    assert "should_floor_memprocfs_memonly" in rp
    assert "run_memprocfs" in rp


def test_binary_availability_helper_exists():
    from sift_sentinel.tools import generic
    assert hasattr(generic, "memprocfs_binary_available")
    # must be callable and return a bool without raising
    assert isinstance(generic.memprocfs_binary_available(), bool)
