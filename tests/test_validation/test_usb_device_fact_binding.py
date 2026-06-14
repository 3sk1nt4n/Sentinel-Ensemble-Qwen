"""usb_device_fact binds end-to-end through the UNIVERSAL typed validator and is a
registered validation family -- no per-tool validator code. A typed_fact claim that
cites the USBSTOR registry path resolves to the compiled usb_device_fact via the
existing by_registry_path / by_fact_signature indexes. Universal: registry structure
only, no case data.
"""
from sift_sentinel.analysis.evidence_db import build_typed_evidence_db
from sift_sentinel.analysis.validation_family_registry import (
    get_validation_family_registry,
)
from sift_sentinel.validation.typed_validator import TypedEvidenceDB, _t_typed_fact


def _db():
    return build_typed_evidence_db({"parse_usb_devices": {"records": [
        {"type": "usb_device", "serial": "AABBCCDD1122", "vendor": "Acme",
         "product": "FlashMax",
         "registry_path": r"HKLM\SYSTEM\ControlSet001\Enum\USBSTOR"
                          r"\Disk&Ven_Acme&Prod_FlashMax&Rev_1\AABBCCDD1122"},
    ], "record_count": 1}})


def test_usb_family_is_registered_for_the_tool():
    reg = get_validation_family_registry()
    assert "usb_device_fact" in reg
    fam = reg["usb_device_fact"]
    producers = fam["producer_tools"] if isinstance(fam, dict) else fam.producer_tools
    assert "parse_usb_devices" in producers


def test_usb_claim_binds_via_registry_path():
    tdb = TypedEvidenceDB(_db())
    claim = {
        "type": "typed_fact",
        "fact_type": "usb_device_fact",
        "value": r"HKLM\SYSTEM\ControlSet001\Enum\USBSTOR"
                 r"\Disk&Ven_Acme&Prod_FlashMax&Rev_1\AABBCCDD1122",
    }
    res = _t_typed_fact(claim, tdb)
    assert res and res[0] == "MATCH", res


def test_usb_claim_no_false_match_for_absent_device():
    tdb = TypedEvidenceDB(_db())
    claim = {
        "type": "typed_fact",
        "fact_type": "usb_device_fact",
        "value": r"HKLM\SYSTEM\ControlSet001\Enum\USBSTOR\Disk&Ven_Other&Prod_None\ZZZZ",
    }
    assert _t_typed_fact(claim, tdb) is None
