"""Service identity as a dedup/reconcile key: two findings about the SAME
Windows service (one citing the install event, one citing the Services
registry key, one citing an explicit service_name claim) must share an
identity key, so they merge / reconcile instead of shipping as duplicates.

Live defect SHAPE: a service-install surfaced twice -- both findings cited
the same Event 7045 record -- because service-name was not a key family
(event-identity needs event_id + identical-second timestamps; siblings that
cite the registry Services key or carry prose values never intersected).

Universal: OS-primitive grammars only -- the Services registry path tail,
the Event 7045 'Service Name:' field grammar, an explicit service_name
claim field. No case data. Kill-switch SIFT_DEDUP_SERVICE_KEYS=0.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.confirmed_dedup import entity_keys  # noqa: E402


def test_explicit_service_name_claim_yields_key():
    f = {"finding_id": "F019", "claims": [
        {"type": "service", "service_name": "examplesvc", "value": "service install"},
    ]}
    assert "svc:examplesvc" in entity_keys(f)


def test_registry_services_path_tail_yields_same_key():
    f = {"finding_id": "F049", "claims": [
        {"type": "registry", "value":
         "HKLM\\SYSTEM\\CurrentControlSet\\Services\\ExampleSvc\\ImagePath"},
    ]}
    assert "svc:examplesvc" in entity_keys(f)


def test_event_7045_service_name_grammar_in_excerpt_yields_same_key():
    f = {"finding_id": "F050",
         "raw_excerpt": "7045|Service Name: ExampleSvc|Image Path: c:\\temp\\x.exe",
         "claims": [{"type": "event_log", "event_id": 7045,
                     "value": "Service installation event"}]}
    assert "svc:examplesvc" in entity_keys(f)


def test_install_event_and_registry_sibling_share_identity():
    a = {"finding_id": "F019",
         "raw_excerpt": "Service Name: ExampleSvc | start type changed",
         "claims": [{"type": "event_log", "event_id": 7045, "value": "install"}]}
    b = {"finding_id": "F049", "claims": [
        {"type": "registry", "value":
         "HKLM\\SYSTEM\\ControlSet001\\Services\\examplesvc"},
    ]}
    assert entity_keys(a) & entity_keys(b)


def test_different_services_never_share_a_key():
    a = {"finding_id": "F1", "claims": [
        {"type": "service", "service_name": "svc-alpha"}]}
    b = {"finding_id": "F2", "claims": [
        {"type": "service", "service_name": "svc-beta"}]}
    assert not (entity_keys(a) & entity_keys(b))


def test_no_service_signal_yields_no_svc_key():
    f = {"finding_id": "F3",
         "raw_excerpt": "process listening on port 4444",
         "claims": [{"type": "pid", "pid": 4, "process": "x.exe"}]}
    assert not any(k.startswith("svc:") for k in entity_keys(f))


def test_generic_or_degenerate_names_rejected():
    # a 1-char or purely-numeric tail must never become an identity
    f = {"finding_id": "F4", "claims": [
        {"type": "registry", "value": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\1"},
    ]}
    assert not any(k.startswith("svc:") for k in entity_keys(f))


def test_kill_switch(monkeypatch):
    monkeypatch.setenv("SIFT_DEDUP_SERVICE_KEYS", "0")
    f = {"finding_id": "F5", "claims": [
        {"type": "service", "service_name": "examplesvc"}]}
    assert not any(k.startswith("svc:") for k in entity_keys(f))
