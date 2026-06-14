"""usb_device_fact compiler (the disk-strong USB story, wired to the typed DB).

USBSTOR serial+vendor/product, MountedDevices drive letter, and per-user
MountPoints2 volume->user become first-class typed facts that bind via the
UNIVERSAL by_fact_signature anchor plus by_registry_path / by_user entity
indexes -- no per-tool validator needed. Universal: keyed on the registry
structure of removable-media artifacts, no case data.
"""
from sift_sentinel.analysis.evidence_db import build_typed_evidence_db, FACT_TYPES


def _outputs(records):
    return {"parse_usb_devices": {"records": records, "record_count": len(records)}}


# Synthetic, dataset-agnostic USB records (vendor/serial are invented placeholders).
USB = [
    {"type": "usb_device", "serial": "AABBCCDD1122", "vendor": "Acme",
     "product": "FlashMax", "friendly_name": "Acme FlashMax USB Device",
     "registry_path": r"HKLM\SYSTEM\ControlSet001\Enum\USBSTOR"
                      r"\Disk&Ven_Acme&Prod_FlashMax&Rev_1\AABBCCDD1122"},
    {"type": "mounted_device", "drive_letter": "E:",
     "registry_path": r"HKLM\SYSTEM\MountedDevices"},
    {"type": "mount_point", "volume": "{guid-1}", "user": "analyst",
     "registry_path": r"HKCU\...\Explorer\MountPoints2\{guid-1}"},
]


def test_usb_device_fact_is_a_known_type():
    assert "usb_device_fact" in FACT_TYPES


def test_compiles_three_usb_records_to_facts():
    db = build_typed_evidence_db(_outputs(USB))
    facts = db["typed_facts"]["usb_device_fact"]
    assert len(facts) == 3
    # fields are flattened onto the fact object
    serials = {f["serial"] for f in facts if f["device_kind"] == "usb_device"}
    assert serials == {"AABBCCDD1122"}
    dev = next(f for f in facts if f["device_kind"] == "usb_device")
    assert dev["vendor"] == "Acme" and dev["product"] == "FlashMax"
    assert "FlashMax" in dev["friendly_name"]


def test_usb_fact_binds_via_fact_signature_and_indexes():
    db = build_typed_evidence_db(_outputs(USB))
    # universal anchor: every usb fact is reachable via by_fact_signature
    sig_ids = {fid for ids in db["indexes"]["by_fact_signature"].values() for fid in ids}
    usb_ids = {f["fact_id"] for f in db["typed_facts"]["usb_device_fact"]}
    assert usb_ids <= sig_ids
    # registry path + per-user entity indexes are populated for richer binding
    assert any("usbstor" in k for k in db["indexes"]["by_registry_path"])
    assert "analyst" in db["indexes"]["by_user"]


def test_empty_and_missing_entity_are_safe():
    assert build_typed_evidence_db(_outputs([]))["typed_facts"]["usb_device_fact"] == []
    # a record with no identity at all is dropped, never raises
    db = build_typed_evidence_db(_outputs([{"type": "usb_device"}]))
    assert db["typed_facts"]["usb_device_fact"] == []
