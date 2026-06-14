"""executes_from_temp_path must fire on the executing IMAGE path, never on a path the process
merely references. A file HANDLE views as subtype 'file' but its authoritative fact_type is
'handle_fact' -- guard by fact_type, not the viewed subtype. Dataset-agnostic: fact shapes only."""
from sift_sentinel.analysis.malicious_semantics import match_executes_from_temp_path as m
def test_file_handle_to_temp_does_not_fire():
    h={"fact_type":"handle_fact",
       "canonical_entity_id":"handle:pid:1:file:\\device\\harddiskvolume3\\programdata\\intel\\shadercache\\x",
       "raw_excerpt":"Name: \\Device\\HarddiskVolume3\\ProgramData\\Intel\\ShaderCache\\x"}
    assert m(h) is False
def test_dll_load_from_temp_does_not_fire():
    d={"fact_type":"dll_load_fact",
       "canonical_entity_id":"dll:pid:1:path:c:/programdata/microsoft/x.dll",
       "raw_excerpt":"c:/programdata/microsoft/x.dll"}
    assert m(d) is False
