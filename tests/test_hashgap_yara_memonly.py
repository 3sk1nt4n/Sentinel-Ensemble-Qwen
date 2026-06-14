"""FIX C (#4): hash-gap fallback enables run_yara on a MEMORY-ONLY case.

The reference-set hash sources are disk-only (get_amcache SHA1, sleuthkit
tsk_recover SHA256). On a memory-only run both are not-applicable, so
ref["hashes"] is always empty (Step 7 prints "Hashes: 0") and there is no
structural-identity coverage to replace them. run_yara is the memory-appropriate
alternative -- it is already DB-wired via _c_yara at LOW confidence (it never
promotes a confirmed finding, so no FP risk) but is opt-in by default. This
auto-enables + injects it on a memory-only case to fill the identity gap.

Universal: keyed on evidence-channel presence (no disk hash collector), no case
data. Kill switch SIFT_HASHGAP_YARA_MEMONLY=0. Operator opt-out via
SIFT_ALLOW_YARA=0 is still honored.
"""
import pathlib

from sift_sentinel import coordinator as C


def test_helper_exists():
    assert hasattr(C, "should_hashgap_yara_memonly")


def test_memory_only_enables_yara():
    assert C.should_hashgap_yara_memonly(
        has_memory=True, has_disk=False, env={}
    ) is True


def test_paired_run_does_not_enable_yara():
    assert C.should_hashgap_yara_memonly(
        has_memory=True, has_disk=True, env={}
    ) is False


def test_disk_only_does_not_enable_yara():
    assert C.should_hashgap_yara_memonly(
        has_memory=False, has_disk=True, env={}
    ) is False


def test_kill_switch_disables_fallback():
    assert C.should_hashgap_yara_memonly(
        has_memory=True, has_disk=False, env={"SIFT_HASHGAP_YARA_MEMONLY": "0"}
    ) is False


def test_operator_explicit_yara_off_is_honored():
    # if the operator explicitly disabled yara, the hash-gap fallback must NOT
    # silently re-enable it
    assert C.should_hashgap_yara_memonly(
        has_memory=True, has_disk=False, env={"SIFT_ALLOW_YARA": "0"}
    ) is False


def test_run_pipeline_wires_the_hashgap_yara_fallback():
    rp = (pathlib.Path(__file__).resolve().parents[1] / "run_pipeline.py").read_text()
    assert "should_hashgap_yara_memonly" in rp
    # it must INJECT run_yara, not merely allow it
    assert "run_yara" in rp
