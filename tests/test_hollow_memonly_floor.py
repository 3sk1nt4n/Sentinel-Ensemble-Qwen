"""FIX A (#2): vol_hollowprocesses is FLOORED on a MEMORY-ONLY case.

Rationale: the USB-WIRE change removed vol_hollowprocesses from the unconditional
31K floor because on a PAIRED / disk-present run it routinely times out and the
process-hollowing/injection class is already covered by the mandatory malfind
prefix + the psxview/ldrmodules pairing. But on a MEMORY-ONLY case the disk
floor tools (parse_usb_devices / parse_rdp_artifacts / sleuthkit_tsk_recover /
parse_userassist) are all not-applicable, so hollowing (T1055.012) has NO
deterministic floor. This re-floors it ONLY for memory-only runs, and only below
the big-memory threshold (on a huge image it still times out and malfind+psxview
cover it -- consistent with big_mem_prune). Universal: keyed on evidence-channel
presence + image size, no case data. Kill switch SIFT_FLOOR_HOLLOW_MEMONLY=0.

The helper is a pure function so the policy is unit-tested directly (the call
site in run_pipeline.py's module-level 31K block is exercised structurally).
"""
import pathlib

from sift_sentinel import coordinator as C


def test_helper_exists():
    assert hasattr(C, "should_floor_hollow_memonly")


def test_memory_only_small_image_floors_hollow():
    # memory present, no disk, small image -> floor it
    assert C.should_floor_hollow_memonly(
        has_memory=True, has_disk=False, mem_gb=2.0, env={}
    ) is True


def test_paired_run_does_not_floor_hollow():
    # disk present -> the USB-WIRE rationale stands; do NOT floor (malfind+psxview cover it)
    assert C.should_floor_hollow_memonly(
        has_memory=True, has_disk=True, mem_gb=2.0, env={}
    ) is False


def test_disk_only_does_not_floor_hollow():
    assert C.should_floor_hollow_memonly(
        has_memory=False, has_disk=True, mem_gb=0.0, env={}
    ) is False


def test_big_memory_image_does_not_floor_hollow():
    # >= big-mem threshold: hollow times out, malfind+psxview cover it (matches big_mem_prune)
    assert C.should_floor_hollow_memonly(
        has_memory=True, has_disk=False, mem_gb=16.0, env={}
    ) is False


def test_big_mem_threshold_env_override_respected():
    # custom threshold via SIFT_BIG_MEM_GB (same knob big_mem_prune reads)
    assert C.should_floor_hollow_memonly(
        has_memory=True, has_disk=False, mem_gb=5.0, env={"SIFT_BIG_MEM_GB": "4"}
    ) is False
    assert C.should_floor_hollow_memonly(
        has_memory=True, has_disk=False, mem_gb=3.0, env={"SIFT_BIG_MEM_GB": "4"}
    ) is True


def test_kill_switch_disables_floor():
    assert C.should_floor_hollow_memonly(
        has_memory=True, has_disk=False, mem_gb=2.0,
        env={"SIFT_FLOOR_HOLLOW_MEMONLY": "0"},
    ) is False


def test_run_pipeline_wires_the_memonly_hollow_floor():
    # the module-level 31K block calls the helper and injects vol_hollowprocesses
    rp = (pathlib.Path(__file__).resolve().parents[1] / "run_pipeline.py").read_text()
    assert "should_floor_hollow_memonly" in rp
    assert "vol_hollowprocesses" in rp


def test_unconditional_floor_tuple_still_excludes_hollow():
    # the memory-only floor is a SEPARATE block; the unconditional priority tuple
    # must still NOT contain hollow (paired/disk behavior preserved). This mirrors
    # the invariant in test_floored_evil_detectors and must not regress.
    rp = (pathlib.Path(__file__).resolve().parents[1] / "run_pipeline.py").read_text()
    floor_region = rp.split("_slot31k_priority_add = (", 1)[1].split("\n)", 1)[0]
    assert '"vol_hollowprocesses"' not in floor_region
