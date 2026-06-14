"""executes_from_temp_path means the process IMAGE executes from a transient path -- not
merely holding a handle to, or loading a DLL from, a file there. handle_fact/dll_load_fact
(resource references) must not raise it. Dataset-agnostic: fact-type taxonomy only."""
from sift_sentinel.analysis.malicious_semantics import match_executes_from_temp_path as m
def test_handle_to_staging_file_does_not_fire():
    assert m({"fact_type":"handle_fact","path":"\\ProgramData\\Intel\\ShaderCache\\Teams_1"}) is False
    assert m({"fact_type":"handle_fact","path":"\\Windows\\Temp\\x.tmp"}) is False
def test_dll_loaded_from_staging_does_not_fire():
    assert m({"fact_type":"dll_load_fact","path":"\\Windows\\Temp\\foo.dll"}) is False
def test_real_execution_facts_still_fire():
    assert m({"fact_type":"file_execution_fact","path":"\\Windows\\Temp\\evil.exe"}) is True
    assert m({"fact_type":"process_fact","image_path":"\\Users\\Public\\payload.exe"}) is True
    assert m({"fact_type":"path","path":"\\Windows\\Temp\\stager.exe"}) is True
def test_non_staging_execution_does_not_fire():
    assert m({"fact_type":"process_fact","image_path":"C:\\Windows\\System32\\svchost.exe"}) is False
