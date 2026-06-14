"""parse_usb_devices live runner: discovers SYSTEM + per-user NTUSER hives on a
mount, opens them, and runs the pure extractor into the standard tool envelope.
Orchestration is tested with synthetic hives (no real registry, no case data);
the user attribution is derived from the NTUSER path, and a bad hive never raises.
"""
from pathlib import Path

import sift_sentinel.tools.parse_usb_devices as m


class _Val:
    def __init__(self, name, value=None): self.name = name; self.value = value


class _Key:
    def __init__(self, name, subkeys=None, values=None):
        self.name = name; self._s = subkeys or []; self._v = values or []
    def subkeys(self): return self._s
    def values(self): return self._v


class _Hive:
    def __init__(self, keys): self._k = keys
    def open_key(self, path): return self._k.get(path)


def _system_hive():
    inst = _Key("4C530000010108119922&0",
                values=[_Val("FriendlyName", "Kingston DataTraveler USB Device")])
    cls = _Key("Disk&Ven_Kingston&Prod_DataTraveler&Rev_PMAP", subkeys=[inst])
    return _Hive({
        r"ControlSet001\Enum\USBSTOR": _Key("USBSTOR", subkeys=[cls]),
        "MountedDevices": _Key("MountedDevices", values=[_Val(r"\DosDevices\E:", b"x")]),
    })


def _ntuser_hive():
    mp = _Key("MountPoints2", subkeys=[_Key("{vol-9}")])
    return _Hive({r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2": mp})


def _make_mount(tmp_path):
    sysp = tmp_path / "Windows" / "System32" / "config" / "SYSTEM"
    sysp.parent.mkdir(parents=True)
    sysp.write_bytes(b"x")
    ntp = tmp_path / "Users" / "user1" / "NTUSER.DAT"
    ntp.parent.mkdir(parents=True)
    ntp.write_bytes(b"x")


def test_runner_orchestrates_system_and_ntuser(tmp_path, monkeypatch):
    _make_mount(tmp_path)

    def fake_open(path):
        return _system_hive() if Path(path).name.upper() == "SYSTEM" else _ntuser_hive()

    monkeypatch.setattr(m, "_reg_open_hive", fake_open)
    env = m.parse_usb_devices(mount_path=str(tmp_path))
    assert env["status"] == "ok"
    assert env["tool_name"] == "parse_usb_devices"
    types = sorted({r["type"] for r in env["records"]})
    assert types == ["mount_point", "mounted_device", "usb_device"]
    mp = next(r for r in env["records"] if r["type"] == "mount_point")
    assert mp["user"] == "user1"             # user derived from the NTUSER path
    dev = next(r for r in env["records"] if r["type"] == "usb_device")
    assert dev["serial"] == "4C530000010108119922" and dev["vendor"] == "Kingston"


def test_runner_resolves_active_disk_mount_from_env(tmp_path, monkeypatch):
    # No mount_path arg (the standalone fn() dispatch) -> USB must resolve the ACTIVE
    # disk mount from SIFT_ACTIVE_DISK_MOUNT (like parse_wmi_subscription /
    # parse_powershell_transcripts) and read the DISK hives, NOT fall back to memory.
    _make_mount(tmp_path)
    monkeypatch.setenv("SIFT_ACTIVE_DISK_MOUNT", str(tmp_path))
    monkeypatch.delenv("SIFT_MEMORY_IMAGE", raising=False)

    def fake_open(path):
        return _system_hive() if Path(path).name.upper() == "SYSTEM" else _ntuser_hive()

    monkeypatch.setattr(m, "_reg_open_hive", fake_open)
    env = m.parse_usb_devices()                  # NO args -> must use the env mount
    assert env["status"] == "ok"
    assert env.get("source") != "memory"         # read DISK, not the memory fallback
    assert any(r["type"] == "usb_device" for r in env["records"])


def test_runner_not_applicable_and_gate_clean_when_no_hives(tmp_path, monkeypatch):
    # No registry hives on the mount AND no memory image -> NOT_APPLICABLE (mirrors
    # registry-persistence), and the envelope must carry NO absolute mount path
    # (PATH_FIDELITY_GATE-safe): only hive basenames, so a no-active-mount run leaves
    # no un-repairable refs.
    monkeypatch.delenv("SIFT_MEMORY_IMAGE", raising=False)
    env = m.parse_usb_devices(mount_path=str(tmp_path))
    assert env["status"] == "not_applicable" and env["record_count"] == 0
    import json
    blob = json.dumps(env)
    assert "/mnt" not in blob and str(tmp_path) not in blob, blob
    assert "searched_hives" in env  # basenames retained for diagnostics


def test_runner_survives_a_bad_hive(tmp_path, monkeypatch):
    _make_mount(tmp_path)

    def boom(path):
        raise OSError("corrupt hive")

    monkeypatch.setattr(m, "_reg_open_hive", boom)
    env = m.parse_usb_devices(mount_path=str(tmp_path))
    assert env["status"] == "empty" and env["errors"]   # errors captured, never raised
