"""Cross-domain: disk-provenance/execution-history signals (temp-path, ShimCache/
AppCompatCache, LNK, JumpList) cannot corroborate a memory-injection finding.
Dataset-agnostic -- signal names only. F003 routes out; genuine memory/behavioural
corroboration stays; pure disk-execution findings untouched."""
from sift_sentinel.analysis.disposition import _rwx_uncorroborated as unc
RWX="rwx_memory_region_with_unusual_protection"; NULL="null_or_empty_cmdline_on_executable"
TEMP="executes_from_temp_path"; SHIM="appcompatcache_execution_from_staging"
LNK="lnk_execution_from_staging"; JUMP="jumplist_access_to_staging"
HOLLOW="process_hollowing_indicators"; C2="outbound_to_known_c2_pattern"

def test_f003_real_signal_set_routes_out():
    assert unc(True, [SHIM,TEMP,JUMP,LNK,NULL,RWX]) is True   # exact F003 set

def test_memory_injection_disk_history_only_routes_out():
    assert unc(True,[RWX,SHIM]) is True
    assert unc(True,[RWX,TEMP]) is True
    assert unc(True,[RWX,LNK,JUMP]) is True
    assert unc(True,[RWX,NULL,TEMP,SHIM]) is True

def test_genuine_memory_corroboration_stays():
    assert unc(True,[RWX,HOLLOW]) is False
    assert unc(True,[RWX,C2]) is False
    assert unc(True,[RWX,NULL,HOLLOW,SHIM]) is False
    assert unc(True,[RWX,HOLLOW,TEMP,LNK,JUMP,SHIM]) is False

def test_pure_disk_execution_findings_untouched():
    assert unc(True,[SHIM]) is False
    assert unc(True,[TEMP]) is False
    assert unc(True,[SHIM,LNK,JUMP]) is False

def test_existing_weak_alone_behavior_preserved():
    assert unc(True,[RWX]) is True
    assert unc(True,[NULL]) is True
    assert unc(True,[RWX,NULL]) is True
    assert unc(False,[]) is False
    assert unc(True,[]) is False
