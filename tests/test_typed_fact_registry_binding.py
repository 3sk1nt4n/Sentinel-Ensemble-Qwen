"""The universal typed_fact binder must bind registry facts via by_registry_path.

The by_registry_path index keys are FORWARD-SLASH, lowercase, value-name-suffixed
(e.g. 'hklm/system/controlset001/control/safeboot/alternateshell'), but
_tf_reg_variants only produced BACKSLASH variants -> registry typed_fact claims
could never match (registry_persistence binds zero, despite 4077 facts + a
populated index). Fix: emit both slash forms so the claim value -- in either
separator -- matches the forward-slash index. Universal: pure key normalization,
no case data. _t_typed_fact stays inert until synthesis emits typed_fact claims,
so this cannot regress existing behavior.
"""
from sift_sentinel.validation.typed_validator import (
    TypedEvidenceDB,
    _t_typed_fact,
    _tf_reg_variants,
)


def _tdb(index_name, key, fact_type):
    edb = {
        "typed_facts": {fact_type: [{"fact_id": "f1", "fact_type": fact_type}]},
        "indexes": {index_name: {key: ["f1"]}},
    }
    return TypedEvidenceDB(edb)


def test_reg_variants_emit_forward_slash_form():
    out = _tf_reg_variants("HKLM\\System\\Control\\SafeBoot\\AlternateShell")
    assert any("/" in v for v in out), out          # forward-slash form present
    assert "hklm/system/control/safeboot/alternateshell" in out


def test_typed_fact_binds_registry_forward_slash_value():
    key = "hklm/software/microsoft/windows nt/currentversion/image file execution options/sethc.exe/debugger"
    tdb = _tdb("by_registry_path", key, "registry_persistence_fact")
    claim = {"type": "typed_fact", "fact_type": "registry_persistence_fact", "value": key}
    res = _t_typed_fact(claim, tdb)
    assert res and res[0] == "MATCH", res


def test_typed_fact_binds_registry_backslash_value_against_forward_slash_index():
    # a claim whose value uses backslashes must still bind the forward-slash index
    key = "hklm/system/controlset001/control/safeboot/alternateshell"
    tdb = _tdb("by_registry_path", key, "registry_persistence_fact")
    claim = {"type": "typed_fact", "fact_type": "registry_persistence_fact",
             "value": "HKLM\\System\\ControlSet001\\Control\\SafeBoot\\AlternateShell"}
    res = _t_typed_fact(claim, tdb)
    assert res and res[0] == "MATCH", res


def test_typed_fact_registry_no_false_match_for_absent_key():
    tdb = _tdb("by_registry_path", "hklm/system/controlset001/services/1394ohci/imagepath",
               "registry_persistence_fact")
    claim = {"type": "typed_fact", "fact_type": "registry_persistence_fact",
             "value": "hklm/software/some/other/key/value"}
    assert _t_typed_fact(claim, tdb) is None
