"""Corroboration gate for confirmed_malicious_atomic (_rwx_uncorroborated). A memory-
injection finding (RWX) needs an INDEPENDENT, same-domain corroborator:
 - weak-alone in-memory signals (private RWX, null/empty cmdline) never confirm alone;
 - disk-execution HISTORY (ShimCache/AppCompatCache, LNK, JumpList) records PAST on-disk
   execution, not live in-memory state -> cannot corroborate injection (cross-domain);
 - a LIVE execution-from-temp and memory/behavioural signals (hollowing, injected thread,
   that process's own C2) DO corroborate.
Updated from the original weak-alone-only assertions per the evidence_db replay that showed
F003's only corroborators were disk-history. Dataset-agnostic: signal taxonomy only."""
from sift_sentinel.analysis.disposition import _rwx_uncorroborated as unc
RWX="rwx_memory_region_with_unusual_protection"; NULL="null_or_empty_cmdline_on_executable"
TEMP="executes_from_temp_path"; SHIM="appcompatcache_execution_from_staging"
LNK="lnk_execution_from_staging"; JUMP="jumplist_access_to_staging"
HOLLOW="process_hollowing_indicators"; C2="outbound_to_known_c2_pattern"
def test_weak_alone_routes_out():
    assert unc(True,[RWX]) is True
    assert unc(True,[NULL]) is True
    assert unc(True,[RWX,NULL]) is True
    assert unc(False,[]) is False
    assert unc(True,[]) is False
def test_memory_or_behavioural_corroboration_stays():
    assert unc(True,[RWX,HOLLOW]) is False
    assert unc(True,[NULL,C2]) is False
    assert unc(True,[RWX,C2]) is False
def test_live_temp_execution_corroborates():
    assert unc(True,[RWX,TEMP]) is False
    assert unc(True,[RWX,NULL,TEMP,SHIM,LNK,JUMP]) is False
def test_disk_history_alone_cannot_corroborate_injection():
    assert unc(True,[RWX,NULL,LNK]) is True
    assert unc(True,[RWX,SHIM]) is True
    assert unc(True,[RWX,NULL,SHIM,LNK,JUMP]) is True
def test_pure_disk_execution_findings_untouched():
    assert unc(True,[SHIM]) is False
    assert unc(True,[LNK,JUMP]) is False
def test_f001_f004_f018_route_out():
    assert unc(True,[NULL,RWX]) is True
    assert unc(True,[NULL]) is True
