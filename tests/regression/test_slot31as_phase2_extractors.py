"""slot31AS regression - dataset-agnostic structural tests.

Property-based: every test uses random tokens or generic structural
patterns. No hardcoded vendor/module/privilege/SID literals. Tests
assert that:
  - extractors produce facts when given well-formed input
  - random tokens pass through verbatim (structural fidelity)
  - no derived classification fields exist (judgment-free)
  - replay against existing tool_outputs/ produces non-empty facts
"""
import secrets
import pytest
from sift_sentinel.analysis.evidence_db import _TOOL_COMPILERS, FACT_TYPES
from sift_sentinel.analysis.phase2_extractors import (
    PHASE2_COMPILERS, PHASE2_FACT_TYPES,
    _c_userassist, _c_privileges, _c_ssdt, _c_getsids, _c_sessions,
)


def test_phase2_compilers_registered():
    for tool in PHASE2_COMPILERS:
        assert tool in _TOOL_COMPILERS, f"{tool} not registered"


def test_phase2_fact_types_present():
    for ft in PHASE2_FACT_TYPES:
        assert ft in FACT_TYPES, f"{ft} not in FACT_TYPES"


def test_userassist_passes_random_tokens_verbatim():
    user_tok = "u" + secrets.token_hex(4)
    path_tok = secrets.token_hex(6)
    name_tok = secrets.token_hex(5)
    recs = [{
        "Hive Name": f"\\??\\C:\\Users\\{user_tok}\\ntuser.dat",
        "Path": f"ntuser.dat\\test\\{path_tok}",
        "Last Write Time": "2024-01-15T10:30:00+00:00",
        "Type": "Key", "Count": 3, "Name": name_tok,
    }]
    facts = [s for _, s, _ in _c_userassist(recs) if s]
    assert len(facts) == 1
    f = facts[0]
    assert f["fact_type"] == "userassist_fact"
    assert f["user"] == user_tok
    assert path_tok in f["registry_path"]
    assert f["entry_name"] == name_tok
    assert f["run_count"] == 3


def test_privileges_passes_random_tokens_verbatim():
    """No is_sensitive/is_enabled - structural only."""
    priv_tok = "Se" + secrets.token_hex(4) + "Privilege"
    attrs_tok = ",".join([secrets.token_hex(3) for _ in range(3)])
    recs = [{
        "PID": 1234, "Process": "test.exe", "Privilege": priv_tok,
        "Attributes": attrs_tok, "Description": "x",
    }]
    facts = [s for _, s, _ in _c_privileges(recs) if s]
    assert len(facts) == 1
    f = facts[0]
    assert f["privilege"] == priv_tok
    assert f["attributes_raw"] == attrs_tok
    # Structural: no judgment fields baked in.
    assert "is_sensitive" not in f
    assert "is_enabled" not in f


def test_ssdt_structural_no_classification():
    """Random module names, no is_hooked field."""
    mod_tok = secrets.token_hex(6)
    sym_tok = "Nt" + secrets.token_hex(4)
    recs = [{"Index": 42, "Module": mod_tok, "Symbol": sym_tok, "Address": 99}]
    facts = [s for _, s, _ in _c_ssdt(recs) if s]
    assert len(facts) == 1
    f = facts[0]
    assert f["module"] == mod_tok
    assert f["symbol"] == sym_tok
    # No judgment.
    assert "is_hooked" not in f


def test_sid_filters_by_format_not_literal():
    """Random valid-SID-shaped strings accepted; malformed dropped."""
    valid_sid = f"S-1-5-{secrets.randbelow(1000)}-{secrets.randbelow(10000)}"
    recs = [
        {"PID": 1, "Process": "a", "SID": valid_sid, "Name": "x"},
        {"PID": 2, "Process": "b", "SID": "not-a-sid", "Name": ""},
        {"PID": 3, "Process": "c", "SID": "Token unreadable", "Name": ""},
        {"PID": 4, "Process": "d", "SID": secrets.token_hex(8), "Name": ""},
    ]
    facts = [s for _, s, _ in _c_getsids(recs) if s]
    assert len(facts) == 1, "only valid-format SID should pass"
    f = facts[0]
    assert f["sid"] == valid_sid
    # No judgment.
    assert "is_system" not in f
    assert "is_user_sid" not in f


def test_sessions_handles_space_keys():
    user_tok = "u" + secrets.token_hex(4)
    proc_tok = secrets.token_hex(4) + ".exe"
    recs = [{
        "Process ID": 1234, "Process": proc_tok,
        "Session ID": 7, "Session Type": "Interactive",
        "User Name": user_tok,
        "Create Time": "2024-01-15T10:00:00+00:00",
    }]
    facts = [s for _, s, _ in _c_sessions(recs) if s]
    assert len(facts) == 1
    f = facts[0]
    assert f["session_id"] == 7
    assert f["user_name"] == user_tok
    assert f["process_name"] == proc_tok


def test_all_extractors_handle_empty_input():
    for compiler in PHASE2_COMPILERS.values():
        assert list(compiler([])) == []


def test_all_extractors_handle_non_dict_records():
    for name, compiler in PHASE2_COMPILERS.items():
        for idx, spec, reason in compiler([None, "x", 42, []]):
            assert spec is None, f"{name} emitted spec for non-dict"
            assert reason, f"{name} no drop_reason for non-dict"


def test_replay_against_live_run_produces_phase2_facts():
    """Real Windows memory image must produce phase2 facts via replay."""
    import os, glob, json
    from sift_sentinel.analysis.evidence_db import build_typed_evidence_db
    runs = sorted([d for d in glob.glob("/tmp/sift-sentinel-run-*")
                   if os.path.isdir(d)])
    if not runs: pytest.skip("no saved run")
    out_dir = runs[-1] + "/tool_outputs/"
    tool_outputs = {}
    for fp in glob.glob(out_dir + "*.json"):
        n = os.path.basename(fp).replace(".json", "")
        try: tool_outputs[n] = json.load(open(fp))
        except: pass
    if not tool_outputs: pytest.skip("no tool_outputs")
    db = build_typed_evidence_db(tool_outputs, reference_set={})
    typed = db.get("typed_facts") or {}
    new_total = sum(len(typed.get(ft, [])) for ft in PHASE2_FACT_TYPES)
    assert new_total > 0, f"phase2 produced 0 facts on real data"
    nonempty_types = [ft for ft in PHASE2_FACT_TYPES if typed.get(ft)]
    assert len(nonempty_types) >= 3, (
        f"only {len(nonempty_types)}/5 phase2 fact_types non-empty: "
        f"{nonempty_types}")
