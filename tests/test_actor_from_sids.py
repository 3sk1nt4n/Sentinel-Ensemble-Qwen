"""WHO from vol_getsids: a finding that references a PID owned by a real user gets a
user_account claim resolved from sid_fact (SID -> user), so service/process findings
finally carry the actor. Universal: account-SID STRUCTURE (S-1-5-21-..-RID>=1000 / 500)
only -- no SID value list, no account-name list. Synthetic SIDs/users (invented).
"""
from sift_sentinel.analysis.finding_actor_time import (
    build_pid_user_map, resolve_actors_from_sids, derive_actor, _is_user_sid,
)


def _db(sid_facts):
    return {"typed_facts": {"sid_fact": sid_facts}}


def test_user_sid_structure_only_real_accounts():
    assert _is_user_sid("S-1-5-21-111-222-333-1001")      # local/domain user
    assert _is_user_sid("S-1-5-21-1-2-3-500")             # built-in Administrator
    assert not _is_user_sid("S-1-5-18")                   # SYSTEM
    assert not _is_user_sid("S-1-5-32-544")               # BUILTIN\Administrators (group)
    assert not _is_user_sid("S-1-5-21-1-2-3-513")         # Domain Users (group, RID<1000)


def test_pid_user_map_picks_the_account_sid():
    facts = [
        {"pid": 4321, "sid": "S-1-5-18", "resolved_name": "NT AUTHORITY\\SYSTEM"},
        {"pid": 4321, "sid": "S-1-5-21-9-9-9-1107", "resolved_name": "ACME\\jdoe"},
        {"pid": 4321, "sid": "S-1-5-32-544", "resolved_name": "BUILTIN\\Administrators"},
    ]
    assert build_pid_user_map(_db(facts)) == {"4321": "jdoe"}     # domain stripped, group/SYSTEM ignored


def test_resolves_actor_onto_a_finding_by_pid_and_never_for_system():
    facts = [
        {"pid": 4321, "sid": "S-1-5-21-9-9-9-1107", "resolved_name": "ACME\\jdoe"},
        {"pid": 4, "sid": "S-1-5-18", "resolved_name": "SYSTEM"},
    ]
    user_finding = {"finding_id": "F1", "title": "proc", "claims": [{"type": "pid", "pid": 4321}]}
    system_finding = {"finding_id": "F2", "title": "svc", "claims": [{"type": "pid", "pid": 4}]}
    n = resolve_actors_from_sids([user_finding, system_finding], _db(facts))
    assert n == 1
    assert derive_actor(user_finding) == "jdoe"       # WHO now present
    assert derive_actor(system_finding) == ""         # SYSTEM process -> no fabricated user


def test_pid_from_text_shape_also_resolves():
    facts = [{"pid": 777, "sid": "S-1-5-21-1-2-3-1200", "resolved_name": "alice"}]
    f = {"finding_id": "F3", "description": "subject ran as pid:777 from a profile path"}
    assert resolve_actors_from_sids([f], _db(facts)) == 1
    assert derive_actor(f) == "alice"


def test_existing_actor_is_not_overwritten_and_empty_db_safe():
    facts = [{"pid": 5, "sid": "S-1-5-21-1-2-3-1500", "resolved_name": "bob"}]
    f = {"claims": [{"type": "user_account", "value": "carol"}, {"type": "pid", "pid": 5}]}
    assert resolve_actors_from_sids([f], _db(facts)) == 0    # already had an actor
    assert derive_actor(f) == "carol"
    assert resolve_actors_from_sids([{"claims": [{"type": "pid", "pid": 5}]}], {}) == 0
