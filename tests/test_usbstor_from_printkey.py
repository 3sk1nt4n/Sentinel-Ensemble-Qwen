"""Memory-carve parser: USBSTOR device identity from a Vol3 windows.registry.printkey
tree (the in-memory SYSTEM hive). Same record shape as the disk extractor so the
downstream compiler/candidate/validator are unchanged. Synthetic printkey fixture
(real STRUCTURE, invented device) -- universal, no case data.
"""
from sift_sentinel.tools.parse_usb_devices import extract_usbstor_from_printkey


def _printkey_tree(serial="11223344AABB", vendor="Acme", product="FlashMax"):
    # mirrors Vol3 printkey --key ...Enum\USBSTOR --recurse on the SYSTEM hive:
    # top-level = device-CLASS keys; each has serial-instance subkeys; each instance
    # carries value rows (FriendlyName wrapped in literal quotes, like Vol3 renders).
    base = r"\Device\HarddiskVolume1\WINDOWS\system32\config\system\ControlSet001\Enum\USBSTOR"
    return [{
        "Type": "Key", "Name": f"Disk&Ven_{vendor}&Prod_{product}&Rev_1024",
        "Key": base,
        "__children": [{
            "Type": "Key", "Name": f"{serial}&0",
            "Key": base + f"\\Disk&Ven_{vendor}&Prod_{product}&Rev_1024",
            "__children": [
                {"Type": "Key", "Name": "Device Parameters", "__children": []},
                {"Type": "REG_SZ", "Name": "DeviceDesc", "Data": '"Disk drive"'},
                {"Type": "REG_SZ", "Name": "FriendlyName", "Data": f'"{vendor} {product} USB Device"'},
            ],
        }],
    }]


def test_parses_serial_vendor_product_friendlyname_from_memory():
    rows = extract_usbstor_from_printkey(_printkey_tree())
    assert len(rows) == 1
    r = rows[0]
    assert r["serial"] == "11223344AABB"          # interface suffix stripped
    assert r["vendor"] == "Acme" and r["product"] == "FlashMax"
    assert r["friendly_name"] == "Acme FlashMax USB Device"   # surrounding quotes stripped
    assert r["source"] == "memory"
    assert "USBSTOR" in r["registry_path"]


def test_ignores_spurious_non_usbstor_or_classless_keys():
    # a cross-hive key match that is NOT a Ven_/Prod_ device class -> no record
    spurious = [{"Type": "Key", "Name": "SomeOtherKey",
                 "Key": r"\...\UsrClass.dat\ControlSet001\Enum\USBSTOR", "__children": []}]
    assert extract_usbstor_from_printkey(spurious) == []
    assert extract_usbstor_from_printkey([]) == []


def test_record_shape_matches_disk_extractor():
    # the memory record must carry the same keys the disk extractor emits, so the
    # usb_device_fact compiler treats memory + disk USB identically.
    rows = extract_usbstor_from_printkey(_printkey_tree())
    for k in ("type", "serial", "vendor", "product", "friendly_name", "registry_path"):
        assert k in rows[0], k
    assert rows[0]["type"] == "usb_device"
