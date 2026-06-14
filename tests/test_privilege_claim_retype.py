"""Privilege-claim retype (universal claim recovery).

The live acme run dropped F030/F031/F032 ("WUDFHost.exe privilege SeImpersonate
enabled", etc.) as "no recognized claim types" -- the AI emitted them as `path`
claims, even though vol_privileges ran and the typed validator already has a fully
wired ``process_privilege_enabled`` checker (matches by process + privilege_name +
enabled against privilege_fact).

normalize_claims retypes a path/raw/artifact claim that structurally describes
"<process> privilege <SePrivilege> enabled/disabled" into process_privilege_enabled
so the EXISTING checker can validate it. Universal: keys on the OS-defined Windows
privilege-name shape (Se[A-Z]...), a process token, and enabled/disabled. No case
data.
"""
from sift_sentinel.validation.normalize_claims import normalize_claims


def _finding(artifact):
    return {"finding_id": "F", "claims": [{"type": "path", "artifact": artifact, "value": artifact}]}


def test_seimpersonate_enabled_retyped():
    out = normalize_claims([_finding("WUDFHost.exe privilege SeImpersonate enabled")])
    c = out[0]["claims"][0]
    assert c["type"] == "process_privilege_enabled"
    assert c["privilege_name"] == "SeImpersonate"
    assert c["process"] == "WUDFHost.exe"
    assert c["enabled"] is True


def test_sedebug_variant_retyped():
    out = normalize_claims([_finding("GoogleCrashHandler.exe with SeDebug privilege enabled")])
    c = out[0]["claims"][0]
    assert c["type"] == "process_privilege_enabled"
    assert c["privilege_name"] == "SeDebug"
    assert c["process"] == "GoogleCrashHandler.exe"
    assert c["enabled"] is True


def test_full_privilege_suffix_form():
    out = normalize_claims([_finding("lsass.exe SeTcbPrivilege enabled")])
    c = out[0]["claims"][0]
    assert c["type"] == "process_privilege_enabled"
    assert c["privilege_name"] in ("SeTcbPrivilege", "SeTcb")


def test_disabled_state_recorded():
    out = normalize_claims([_finding("svc.exe privilege SeBackup disabled")])
    c = out[0]["claims"][0]
    assert c["enabled"] is False


# ── must NOT misfire on real paths / non-privilege text ──────────────────────
def test_real_path_not_retyped():
    out = normalize_claims([_finding("C:/Users/Service/Security/app.exe")])
    assert out[0]["claims"][0]["type"] != "process_privilege_enabled"


def test_path_without_privilege_word_not_retyped():
    # 'SeImpersonate'-shaped token requires the privilege/enabled context to retype
    out = normalize_claims([_finding("C:/Program Files/SeService/runner.exe")])
    assert out[0]["claims"][0]["type"] != "process_privilege_enabled"


def test_existing_typed_claim_untouched():
    f = {"finding_id": "F", "claims": [{"type": "pid", "pid": 8312, "process": "x.exe"}]}
    out = normalize_claims([f])
    assert out[0]["claims"][0]["type"] == "pid"


def test_retyped_claim_validates_against_privilege_fact():
    # end-to-end: the retyped claim is accepted by the EXISTING typed checker when a
    # matching privilege_fact is present.
    from sift_sentinel.validation.typed_validator import TypedEvidenceDB, _TYPED_CHECKERS
    out = normalize_claims([_finding("WUDFHost.exe privilege SeImpersonate enabled")])
    claim = out[0]["claims"][0]
    # real privilege_fact shape: `privilege` (full constant) + `process_name`, and
    # the AI claim's short 'SeImpersonate' must still match via suffix-insensitive norm.
    edb = TypedEvidenceDB({
        "typed_facts": {"privilege_fact": [
            {"fact_id": "pv", "fact_type": "privilege_fact", "pid": 1428,
             "process_name": "wudfhost.exe", "privilege": "SeImpersonatePrivilege",
             "attributes": ["Enabled"]}]},
        "indexes": {"by_pid": {"1428": ["pv"]}},
    })
    status, _ = _TYPED_CHECKERS["process_privilege_enabled"](claim, edb)
    assert status in ("MATCH", "SUPPORTED", "OK", "CONFIRMED"), status
