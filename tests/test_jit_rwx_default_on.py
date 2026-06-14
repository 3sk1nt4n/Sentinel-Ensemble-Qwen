"""JIT-RWX gate is now ON by default (kill-switch SIFT_JIT_RWX=0).

The live acme (Haiku) run surfaced 8 'memory injection' findings on signed
Windows JIT/UWP hosts (SearchApp, LockApp, RuntimeBroker, smartscreen, ...) that
stayed MEDIUM because this conservative, downgrade-only, Rail-1-safe gate was
defaulted OFF. Flipping the default to ON is the universal accuracy fix: it
sweeps clean JIT/UWP RWX FPs to benign while NEVER touching a real injection
(Rail 1 = payload present blocks) or a non-JIT native host (stays inconclusive,
the honest disposition). No process/AV name list -> works on any case.

This locks (a) the run_pipeline default is ON, and (b) the batch sweep behaviour
on a faithful acme-shaped mix.
"""
import re
from pathlib import Path

from sift_sentinel.analysis.jit_rwx_gate import apply_jit_rwx_downgrade, jit_rwx_downgrade
from sift_sentinel.analysis.disposition import derive_final_disposition, BUCKET_BENIGN


def _edb(facts_by_type, by_pid):
    return {"typed_facts": facts_by_type, "indexes": {"by_pid": by_pid}}


def _f(fid, pid):
    return {"finding_id": fid, "title": "memory injection RWX",
            "claims": [{"type": "pid", "pid": pid, "process": "p.exe"}]}


def _mi(pid, char="unknown", corrob=False):
    return {"fact_id": f"mi{pid}", "fact_type": "memory_injection_fact",
            "pid": pid, "characterization": char, "injection_corroborated": corrob}


def _proc(pid, path):
    return {"fact_id": f"p{pid}", "fact_type": "process_fact", "pid": pid, "path": path}


def _dll(pid, name):
    return {"fact_id": f"d{pid}", "fact_type": "dll_load_fact", "pid": pid, "dll_name": name}


def test_run_pipeline_jit_rwx_gate_is_default_on():
    src = Path("run_pipeline.py").read_text()
    m = re.search(r'os\.environ\.get\(\s*"SIFT_JIT_RWX"\s*,\s*"([^"]*)"\s*\)\s*\.strip\(\)\.lower\(\)\s*(not in|in)\b', src)
    assert m, "SIFT_JIT_RWX gate line not found in run_pipeline.py"
    default, op = m.group(1), m.group(2)
    # default-ON pattern: get(..., "1") ... not in ("0","false",...)
    assert default == "1" and op == "not in", (
        f"JIT-RWX gate must be default-ON (got default={default!r} op={op!r})")


def test_acme_batch_sweep_is_universal():
    # A faithful acme-shaped mix processed in ONE batch:
    #   UWP host (SearchApp-like)   -> downgraded (Rail 2 UWP path, no payload)
    #   JIT-DLL host (.NET)         -> downgraded (Rail 2 clr.dll)
    #   native AV host (Defender)   -> NOT downgraded (not a JIT host -> inconclusive)
    #   real injection (rd01-shape) -> NOT downgraded (Rail 1 payload blocks)
    edb = _edb(
        {"memory_injection_fact": [_mi(8312), _mi(100), _mi(4864),
                                   _mi(8712, char="mz_pe", corrob=True)],
         "dll_load_fact": [_dll(100, "coreclr.dll")],
         "process_fact": [
             _proc(8312, "c:/program files/windowsapps/microsoft.searchapp_1/app.exe"),
             _proc(100, "c:/app/managed.exe"),
             _proc(4864, "c:/program files/windows defender/msmpeng.exe"),
             _proc(8712, "c:/windows/system32/notepad.exe"),
         ]},
        {"8312": ["mi8312", "p8312"], "100": ["mi100", "d100", "p100"],
         "4864": ["mi4864", "p4864"], "8712": ["mi8712", "p8712"]})

    findings = [_f("UWP", 8312), _f("NET", 100), _f("AV", 4864), _f("REAL", 8712)]
    n = apply_jit_rwx_downgrade(findings, edb)

    by_id = {f["finding_id"]: f for f in findings}
    assert n == 2                                            # only the two clean JIT hosts
    assert by_id["UWP"].get("_jit_rwx_downgrade") is True
    assert by_id["NET"].get("_jit_rwx_downgrade") is True
    assert by_id["AV"].get("_jit_rwx_downgrade") is not True   # native -> honest inconclusive
    assert by_id["REAL"].get("_jit_rwx_downgrade") is not True  # real injection preserved

    # the gate's universal guarantees, checked at the gate (not via downstream
    # weak-signal routing which a thin test finding would also hit):
    #   - a downgraded JIT host carries the benign-jit override + routes benign
    assert derive_final_disposition(by_id["UWP"], evidence_db=edb)[0] == BUCKET_BENIGN
    #   - the real injection is blocked by Rail 1 (payload), never benign-jit'd
    real_down, real_reason = jit_rwx_downgrade(by_id["REAL"], edb)
    assert real_down is False and "payload" in real_reason
    #   - the native AV host is simply not a JIT host (honest non-suppression)
    av_down, av_reason = jit_rwx_downgrade(by_id["AV"], edb)
    assert av_down is False and "jit_host" in av_reason
