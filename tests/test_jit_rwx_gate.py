"""JIT/UWP benign-RWX gate -- universal, structural, downgrade-only.
The decisive A/B cases: a clean JIT host is downgraded; a REAL injection (payload
or corroborator) is NEVER touched -- regardless of the host. No names, no case data.
"""
from sift_sentinel.analysis.jit_rwx_gate import jit_rwx_downgrade, apply_jit_rwx_downgrade
from sift_sentinel.analysis.disposition import derive_final_disposition, BUCKET_BENIGN


def _edb(facts_by_type, by_pid):
    return {"typed_facts": facts_by_type, "indexes": {"by_pid": by_pid}}


def _f(fid, pid):
    return {"finding_id": fid, "title": "memory injection RWX",
            "claims": [{"type": "pid", "pid": pid, "process": "p.exe"}]}


def test_clean_uwp_jit_host_no_payload_is_downgraded():
    # UWP process, empty RWX (characterization unknown, not corroborated), no egress
    edb = _edb(
        {"memory_injection_fact": [{"fact_id": "mi1", "fact_type": "memory_injection_fact",
                                    "pid": 8312, "characterization": "unknown",
                                    "injection_corroborated": False}],
         "process_fact": [{"fact_id": "p1", "fact_type": "process_fact", "pid": 8312,
                           "path": "c:/program files/windowsapps/microsoft.app_1.0/app.exe"}]},
        {"8312": ["mi1", "p1"]})
    down, reason = jit_rwx_downgrade(_f("F1", 8312), edb)
    assert down is True, reason


def test_jit_dll_host_no_payload_is_downgraded():
    edb = _edb(
        {"memory_injection_fact": [{"fact_id": "mi", "fact_type": "memory_injection_fact",
                                    "pid": 100, "characterization": "unknown",
                                    "injection_corroborated": False}],
         "dll_load_fact": [{"fact_id": "d", "fact_type": "dll_load_fact", "pid": 100,
                            "dll_name": "clr.dll"}],
         "process_fact": [{"fact_id": "p", "fact_type": "process_fact", "pid": 100,
                           "path": "c:/app/x.exe"}]},
        {"100": ["mi", "d", "p"]})
    assert jit_rwx_downgrade(_f("F", 100), edb)[0] is True


def test_real_injection_with_payload_is_never_downgraded():
    # rd01-shape: a genuine PE/shellcode injection -> Rail 1 blocks, even in a JIT host
    edb = _edb(
        {"memory_injection_fact": [{"fact_id": "mi", "fact_type": "memory_injection_fact",
                                    "pid": 8712, "characterization": "mz_pe",
                                    "injection_corroborated": True}],
         "dll_load_fact": [{"fact_id": "d", "fact_type": "dll_load_fact", "pid": 8712,
                            "dll_name": "clr.dll"}],
         "process_fact": [{"fact_id": "p", "fact_type": "process_fact", "pid": 8712,
                           "path": "c:/windows/.../powershell.exe"}]},
        {"8712": ["mi", "d", "p"]})
    down, reason = jit_rwx_downgrade(_f("F", 8712), edb)
    assert down is False and "payload" in reason


def test_external_egress_blocks_downgrade():
    edb = _edb(
        {"memory_injection_fact": [{"fact_id": "mi", "fact_type": "memory_injection_fact",
                                    "pid": 50, "characterization": "unknown",
                                    "injection_corroborated": False}],
         "process_fact": [{"fact_id": "p", "fact_type": "process_fact", "pid": 50,
                           "path": "c:/program files/windowsapps/x_1/app.exe"}],
         "network_connection_fact": [{"fact_id": "n", "fact_type": "network_connection_fact",
                                      "pid": 50, "remote_ip": "203.0.113.9"}]},
        {"50": ["mi", "p", "n"]})
    down, reason = jit_rwx_downgrade(_f("F", 50), edb)
    assert down is False and "egress" in reason


def test_non_jit_host_not_downgraded():
    # a plain exe (not JIT, not UWP) with no-payload RWX -> Rail 2 fails -> stays
    edb = _edb(
        {"memory_injection_fact": [{"fact_id": "mi", "fact_type": "memory_injection_fact",
                                    "pid": 7, "characterization": "unknown",
                                    "injection_corroborated": False}],
         "process_fact": [{"fact_id": "p", "fact_type": "process_fact", "pid": 7,
                           "path": "c:/temp/evil.exe"}]},
        {"7": ["mi", "p"]})
    assert jit_rwx_downgrade(_f("F", 7), edb)[0] is False


def test_flag_routes_to_benign_and_is_inert_by_default():
    edb = _edb(
        {"memory_injection_fact": [{"fact_id": "mi", "fact_type": "memory_injection_fact",
                                    "pid": 8312, "characterization": "unknown",
                                    "injection_corroborated": False}],
         "process_fact": [{"fact_id": "p", "fact_type": "process_fact", "pid": 8312,
                           "path": "c:/program files/windowsapps/m_1/app.exe"}]},
        {"8312": ["mi", "p"]})
    f = _f("F1", 8312)
    g = _f("F2", 8312)
    n = apply_jit_rwx_downgrade([f], edb)
    assert n == 1 and f.get("_jit_rwx_downgrade") is True
    assert derive_final_disposition(f, evidence_db=edb)[0] == BUCKET_BENIGN
    # a finding NOT run through the pass has no flag -> default routing (inert hook)
    assert "_jit_rwx_downgrade" not in g
