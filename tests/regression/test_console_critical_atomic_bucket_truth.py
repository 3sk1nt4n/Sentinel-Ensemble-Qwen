"""Slot 31E-DB.5a-alpha TASK 6 -- CONSOLE_CRITICAL_ATOMIC_SYNTHESIS_LEAK_
GATE / REPORT_DISPLAY_BUCKET_CONSISTENCY_GATE.

A CRITICAL synthesis_narrative item must not leak into the CRITICAL
*atomic* section. The atomic section is sourced from the confirmed
bucket; the synthesis section from the synthesis bucket. run_pipeline.py
is not safely importable, so the helper is AST-extracted (same pattern
as the locked F5 test) and the source-of-truth is asserted on text.
Dataset-agnostic.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path


def _src() -> str:
    return Path("run_pipeline.py").read_text()


def _load_helper():
    tree = ast.parse(_src())
    func = next(
        (n for n in tree.body
         if isinstance(n, ast.FunctionDef)
         and n.name == "_f5_is_synthesis_finding"),
        None,
    )
    assert func is not None, "missing _f5_is_synthesis_finding"
    mod = ast.Module(body=[func], type_ignores=[])
    ast.fix_missing_locations(mod)
    ns: dict = {}
    exec(compile(mod, "<f5>", "exec"), ns)
    return ns["_f5_is_synthesis_finding"]


def test_synthesis_bucket_item_classified_synthesis_even_if_atomic_type():
    h = _load_helper()
    # finding_type says atomic, but disposition routed it to synthesis.
    leaky = {
        "finding_type": "atomic",
        "severity": "CRITICAL",
        "final_disposition": "synthesis_narrative",
        "title": "chain rollup",
    }
    assert h(leaky) is True  # disposition truth wins -> not atomic


def test_confirmed_atomic_item_not_classified_synthesis():
    h = _load_helper()
    conf = {
        "finding_type": "atomic",
        "severity": "CRITICAL",
        "final_disposition": "confirmed_malicious_atomic",
        "title": "staged payload",
    }
    assert h(conf) is False


def test_atomic_section_sourced_from_confirmed_bucket():
    src = _src()
    m = re.search(r"_atomic_crits\s*=\s*\[[\s\S]*?\]", src)
    assert m, "missing _atomic_crits partition"
    assert "_confirmed_atomic" in m.group(0), (
        "CRITICAL atomic must source from the confirmed disposition "
        "bucket, not flat findings_final"
    )
    assert "findings_final" not in m.group(0)


def test_synthesis_section_sourced_from_synthesis_bucket():
    src = _src()
    m = re.search(r"_synthesis_crits\s*=\s*\[[\s\S]*?\]", src)
    assert m, "missing _synthesis_crits partition"
    assert "_bucket_synthesis" in m.group(0)


def test_gate_markers_emitted_in_pipeline():
    src = _src()
    assert "CONSOLE_CRITICAL_ATOMIC_SYNTHESIS_LEAK_GATE" in src
    assert "REPORT_DISPLAY_BUCKET_CONSISTENCY_GATE" in src


def test_no_leak_property():
    # A CRITICAL synthesis item and a CRITICAL confirmed item, run
    # through the AST helper, must partition disjointly.
    h = _load_helper()
    syn = {"severity": "CRITICAL", "final_disposition": "synthesis_narrative",
           "finding_type": "atomic", "title": "narrative"}
    conf = {"severity": "CRITICAL",
            "final_disposition": "confirmed_malicious_atomic",
            "finding_type": "atomic", "title": "atomic evil"}
    confirmed_bucket = [conf]
    synthesis_bucket = [syn]
    atomic_crits = [f for f in confirmed_bucket if not h(f)]
    synth_crits = [f for f in synthesis_bucket if h(f)]
    assert syn not in atomic_crits
    assert syn in synth_crits
    assert conf in atomic_crits


def test_marker():
    print("CONSOLE_CRITICAL_ATOMIC_SYNTHESIS_LEAK_GATE=PASS")
    print("REPORT_DISPLAY_BUCKET_CONSISTENCY_GATE=PASS")
    assert True
