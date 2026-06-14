"""USB/removable device extractor (the disk-strong USB story). Duck-typed synthetic
hives, exactly like the registry-persistence tests. Universal: registry structure only.
"""
from sift_sentinel.tools.parse_usb_devices import (
    extract_usb_devices, extract_usbstor, extract_mounted_devices, extract_mount_points,
)


class _Val:
    def __init__(self, name, value=None): self.name = name; self.value = value


class _Key:
    def __init__(self, name, subkeys=None, values=None):
        self.name = name; self._sub = subkeys or []; self._val = values or []
    def subkeys(self): return self._sub
    def values(self): return self._val


class _Hive:
    """open_key(path) -> _Key, walking a dict of path -> _Key."""
    def __init__(self, keys): self._keys = keys
    def open_key(self, path): return self._keys.get(path)


def _system_with_usbstor():
    inst = _Key("4C530000010108119922&0", values=[_Val("FriendlyName", "Kingston DataTraveler USB Device")])
    cls = _Key("Disk&Ven_Kingston&Prod_DataTraveler&Rev_PMAP", subkeys=[inst])
    usbstor = _Key("USBSTOR", subkeys=[cls])
    md = _Key("MountedDevices", values=[_Val(r"\DosDevices\E:", b"x"), _Val(r"\??\Volume{abc}", b"y")])
    return _Hive({r"ControlSet001\Enum\USBSTOR": usbstor, "MountedDevices": md})


def test_usbstor_serial_vendor_product_friendlyname():
    rows = extract_usbstor(_system_with_usbstor())
    assert len(rows) == 1
    r = rows[0]
    assert r["serial"] == "4C530000010108119922"        # interface suffix stripped
    assert r["vendor"] == "Kingston" and r["product"] == "DataTraveler"
    assert "DataTraveler" in r["friendly_name"]
    assert "USBSTOR" in r["registry_path"]


def test_mounted_devices_drive_letters_only():
    rows = extract_mounted_devices(_system_with_usbstor())
    assert [r["drive_letter"] for r in rows] == ["E:"]    # the Volume{} value is not a drive letter


def test_mount_points_tie_volume_to_user():
    mp = _Key("MountPoints2", subkeys=[_Key("{abc-123}"), _Key("CPC")])  # CPC is not a volume GUID
    ntuser = _Hive({r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2": mp})
    rows = extract_mount_points(ntuser, user="user1")
    assert len(rows) == 1
    assert rows[0]["volume"] == "{abc-123}" and rows[0]["user"] == "user1"


def test_extract_all_combines_and_is_empty_safe():
    rows = extract_usb_devices(_system_with_usbstor(),
                               {"user1": _Hive({r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2":
                                                  _Key("MountPoints2", subkeys=[_Key("{vol-9}")])})})
    types = sorted({r["type"] for r in rows})
    assert types == ["mount_point", "mounted_device", "usb_device"]
    # empty / absent hives never raise
    assert extract_usb_devices(None, None) == []
    assert extract_usb_devices(_Hive({})) == []
