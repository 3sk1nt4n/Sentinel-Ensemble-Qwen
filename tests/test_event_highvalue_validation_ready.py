"""Highest-value DISK/event signals must reach validation-ready.

The event_log compiler scores several textbook Find-Evil indicators but several were not in
_is_strong_ready (and two mapped to context_only), so they never reached validation-ready:
  - 7045 service installed from a temp/non-standard path (PsExec / T1543)
  - 7045 kernel driver from a non-standard path (rootkit)
  - 1102/104 audit-log cleared (T1070.001 anti-forensics)
These are unambiguous and low-FP -> promoted.

FP discipline (the F-Response lesson): admin-share access (C$/ADMIN$, T1021.002) and
privileged-group modification (T1098) are genuinely DUAL-USE -- legit admin tooling hits
admin shares and adds users constantly -- so they stay CORROBORATING, never strong-ready
alone. Universal: keyed on Event IDs + path/group shape, no case data.
"""
import json

from sift_sentinel.analysis.candidate_observations import (
    build_candidate_observations,
    _is_strong_ready,
    _candidate_type,
)


def _evt(eid, msg):
    rx = {"EventID": eid, "Message": msg}
    return {"fact_id": "e_%s" % eid, "source_tool": "parse_event_logs",
            "fact_type": "event_log_fact", "raw_excerpt": json.dumps(rx)}


def _ready(fact):
    r = build_candidate_observations({"typed_facts": {"event_log_fact": [fact]}})
    return any(c.get("validation_ready") for c in r["candidates"])


# ---- promoted: unambiguous evil reaches validation-ready ----
def test_service_install_from_temp_is_validation_ready():
    assert _ready(_evt("7045", "A service was installed. ImagePath: C:\\Windows\\Temp\\evil.exe")) is True


def test_kernel_driver_from_temp_is_validation_ready():
    assert _ready(_evt("7045", "A service was installed. ImagePath: C:\\Windows\\Temp\\rk.sys")) is True


def test_log_clearing_is_validation_ready():
    assert _ready(_evt("1102", "The audit log was cleared")) is True


# ---- FP discipline: dual-use stays corroborating (NOT ready alone) ----
def test_admin_share_access_stays_corroborating():
    assert _ready(_evt("5140", "A network share object was accessed \\\\host\\C$")) is False


def test_priv_group_modification_stays_corroborating():
    assert _ready(_evt("4732", "A member was added to the Administrators security group")) is False


# ---- predicate-level guards ----
def test_strong_ready_membership():
    assert _is_strong_ready({"anti_forensics_execution"})
    assert _is_strong_ready({"event_service_install_abnormal"})
    assert _is_strong_ready({"event_kernel_driver_nonstandard_path"})
    assert not _is_strong_ready({"admin_share_access"})
    assert not _is_strong_ready({"privileged_group_modification"})


def test_service_install_is_not_context_only_type():
    assert _candidate_type({"event_service_install_abnormal"}) != "context_only"
    assert _candidate_type({"event_kernel_driver_nonstandard_path"}) != "context_only"
