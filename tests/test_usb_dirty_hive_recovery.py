"""USB parsing on DIRTY hives: parse failures must never read as 'no devices'.

A SYSTEM hive imaged from a live box routinely carries unreplayed
transaction logs (SYSTEM.LOG1/LOG2); python-registry then raises a
ParseException on the very key that matters (Enum\\USBSTOR) and the old code
swallowed it into status='empty' -- a silent false negative on the classic
insider-exfil artifact. Required behaviour:

  1. key ABSENT (RegistryKeyNotFoundException)  -> clean empty, no fallback
  2. key UNPARSEABLE + RECmd replay recovers    -> records + provenance
  3. key UNPARSEABLE + no recovery possible     -> status 'error' with reason
     (degraded, surfaced by ZERO_RECORD gate -- never a fake-clean zero)

Universal: keyed on exception classification + registry structure; the RECmd
JSON parser is exercised on synthetic vendor/product/serial values only.
"""
from __future__ import annotations

import sift_sentinel.tools.parse_usb_devices as usb


# ── fakes ────────────────────────────────────────────────────────────────

class _KeyNotFound(Exception):
    pass


_KeyNotFound.__name__ = "RegistryKeyNotFoundException"


class _ParseBoom(Exception):
    pass


_ParseBoom.__name__ = "ParseException"


class _FakeReg:
    """python-registry stand-in: open(path) raises per the configured map."""

    def __init__(self, behavior):
        self._behavior = behavior          # path-substring -> exception | key

    def open(self, path):
        for frag, beh in self._behavior.items():
            if frag.lower() in path.lower():
                if isinstance(beh, type) and issubclass(beh, Exception):
                    raise beh(path)
                return beh
        raise _KeyNotFound(path)


def _adapter(behavior):
    return usb._RegistryHiveAdapter(_FakeReg(behavior))


# ── 1. adapter classifies absent vs unparseable ─────────────────────────

def test_adapter_absent_key_is_not_a_parse_error():
    a = _adapter({})                                  # everything absent
    assert a.open_key(r"ControlSet001\Enum\USBSTOR") is None
    assert a.parse_errors == []


def test_adapter_parse_exception_is_recorded():
    a = _adapter({"usbstor": _ParseBoom})
    assert a.open_key(r"ControlSet001\Enum\USBSTOR") is None
    assert len(a.parse_errors) == 1
    assert "USBSTOR" in a.parse_errors[0]["path"]
    assert "ParseException" in a.parse_errors[0]["error"]


class _IterBoomKey:
    """Key that OPENS fine but raises on iteration -- the real dirty-hive
    shape: child cells pending in the transaction logs."""

    def subkeys(self):
        raise _ParseBoom("Invalid NK Record ID")

    def values(self):
        return []


def test_iteration_level_parse_failure_recorded_on_hive():
    a = _adapter({"usbstor": _IterBoomKey()})
    recs = usb.extract_usbstor(a, "ControlSet001")
    assert recs == []
    assert len(a.parse_errors) == 1
    assert "USBSTOR" in a.parse_errors[0]["path"].upper()
    assert "ParseException" in a.parse_errors[0]["error"]


# ── 2. RECmd JSON parsing (pure, synthetic) ──────────────────────────────

def _recmd_json(vendor="TestVen", product="TestProd", serial="SER01"):
    return {
        "KeyPath": "ROOT\\ControlSet001\\Enum\\USBSTOR",
        "KeyName": "USBSTOR",
        "SubKeys": [{
            "KeyPath": f"ROOT\\ControlSet001\\Enum\\USBSTOR\\Disk&Ven_{vendor}&Prod_{product}&Rev_1.0",
            "KeyName": f"Disk&Ven_{vendor}&Prod_{product}&Rev_1.0",
            "LastWriteTimestamp": "2020-01-02 03:04:05.0000000",
            "SubKeys": [{
                "KeyPath": "...\\" + serial + "&0",
                "KeyName": serial + "&0",
                "LastWriteTimestamp": "2020-01-02 03:04:06.0000000",
                "SubKeys": [],
                "Values": [
                    {"ValueName": "FriendlyName",
                     "ValueData": vendor + " " + product + " USB Device"},
                ],
            }],
            "Values": [],
        }],
        "Values": [],
    }


def test_recmd_json_parser_extracts_device_identity():
    recs = usb._parse_recmd_usbstor_json(_recmd_json(), "ControlSet001")
    assert len(recs) == 1
    r = recs[0]
    assert r["type"] == "usb_device"
    assert r["vendor"] == "TestVen"
    assert r["product"] == "TestProd"
    assert r["serial"] == "SER01"
    assert "TestVen TestProd" in r["friendly_name"]
    assert r["recovered_via"] == "registry_transaction_log_replay"
    assert r["last_write"].startswith("2020-01-02")


def test_recmd_json_parser_metamorphic_relabel():
    a = usb._parse_recmd_usbstor_json(_recmd_json("VenA", "ProdA", "AAA1"),
                                      "ControlSet001")
    b = usb._parse_recmd_usbstor_json(_recmd_json("VenB", "ProdB", "BBB2"),
                                      "ControlSet001")
    assert {k for k in a[0]} == {k for k in b[0]}
    assert a[0]["serial"] == "AAA1" and b[0]["serial"] == "BBB2"


# ── 3. runner end-to-end on a dirty hive ────────────────────────────────

def _run_with(monkeypatch, tmp_path, behavior, recmd_result):
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"regf-stub")
    calls = []

    def fake_recover(path, control_set="ControlSet001", timeout_s=120):
        calls.append(str(path))
        return list(recmd_result)

    monkeypatch.setattr(usb, "_usbstor_via_recmd", fake_recover)
    monkeypatch.setattr(
        usb, "_reg_hive_candidates", lambda mp, hp: [hive])
    monkeypatch.setattr(
        usb, "_reg_open_hive", lambda p: _FakeReg(behavior))
    monkeypatch.delenv("SIFT_USB_RECMD_FALLBACK", raising=False)
    env = usb.parse_usb_devices(mount_path=str(tmp_path))
    return env, calls


_RECOVERED = [{
    "type": "usb_device", "serial": "SER01", "vendor": "TestVen",
    "product": "TestProd", "friendly_name": "",
    "registry_path": r"HKLM\SYSTEM\ControlSet001\Enum\USBSTOR\X\SER01",
    "recovered_via": "registry_transaction_log_replay",
}]


def test_dirty_hive_recovers_via_recmd(monkeypatch, tmp_path):
    env, calls = _run_with(monkeypatch, tmp_path,
                           {"usbstor": _ParseBoom}, _RECOVERED)
    assert calls, "RECmd fallback was not attempted on a parse failure"
    assert env["status"] == "ok"
    assert env["record_count"] == 1
    assert env["records"][0]["recovered_via"] == \
        "registry_transaction_log_replay"


def test_dirty_hive_unrecovered_is_error_not_empty(monkeypatch, tmp_path):
    env, calls = _run_with(monkeypatch, tmp_path,
                           {"usbstor": _ParseBoom}, [])
    assert calls
    assert env["status"] == "error"          # degraded -- NEVER fake-clean
    assert "unparseable" in str(env.get("reason", "")).lower()
    assert env["record_count"] == 0


def test_absent_usbstor_stays_clean_empty_without_fallback(monkeypatch,
                                                           tmp_path):
    env, calls = _run_with(monkeypatch, tmp_path, {}, _RECOVERED)
    assert calls == [], "fallback must not fire when the key is simply absent"
    assert env["status"] == "empty"


def test_kill_switch_disables_fallback(monkeypatch, tmp_path):
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"regf-stub")
    calls = []
    monkeypatch.setattr(usb, "_usbstor_via_recmd",
                        lambda *a, **k: calls.append(1) or [])
    monkeypatch.setattr(usb, "_reg_hive_candidates", lambda mp, hp: [hive])
    monkeypatch.setattr(usb, "_reg_open_hive",
                        lambda p: _FakeReg({"usbstor": _ParseBoom}))
    monkeypatch.setenv("SIFT_USB_RECMD_FALLBACK", "0")
    env = usb.parse_usb_devices(mount_path=str(tmp_path))
    assert calls == []
    assert env["status"] == "error"           # still honest, just no recovery
