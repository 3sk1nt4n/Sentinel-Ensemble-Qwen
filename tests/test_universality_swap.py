"""Universality (anti-answer-key) proof for the USB / UserAssist / bulk / DGA work.

The decisive test of "is this universal or secretly tuned to one dataset?" is
METAMORPHIC INVARIANCE: relabel every case-specific value (serial, vendor, program,
domain, user) and the structural verdict must be UNCHANGED. If behavior depends only
on STRUCTURE (registry key shape, ROT13, entropy/vowel math) and not on the specific
values, the detector generalizes to a held-out box. All inputs here are invented --
no case data -- and several DISTINCT relabelings are checked so no single value can be
memorized.
"""
import codecs

from sift_sentinel.analysis.dga_detection import dga_score
from sift_sentinel.tools.parse_usb_devices import extract_usbstor_from_printkey
from sift_sentinel.tools.parse_userassist import _rot13, extract_userassist


# ── DGA: keys on low-vowel/entropy STRUCTURE, not a domain list ───────────
def test_dga_flags_any_random_label_regardless_of_value():
    # 5 DISTINCT random low-vowel labels, different chars + different TLDs -> all flag
    for d in ("kqzxvbnmlprst.com", "wbtfpqhzxlmn.net", "zxcvbnmqwrtp.org",
              "mnbvcxzlkjhg.io", "ghjklzxcvbnm.biz"):
        assert dga_score(d)[0], d


def test_dga_spares_any_brandable_label_regardless_of_value():
    # 5 DISTINCT benign brandable labels -> none flag (it is NOT a domain blocklist)
    for d in ("cloudbackup.com", "onlinebanking.net", "securemail.org",
              "printserver.io", "exampleservice.biz"):
        assert not dga_score(d)[0], d


# ── USB: pure pass-through of whatever sits in the USBSTOR key shape ───────
def _usbstor_printkey(vendor, product, serial):
    base = r"\...\system\ControlSet001\Enum\USBSTOR"
    return [{
        "Type": "Key", "Name": f"Disk&Ven_{vendor}&Prod_{product}&Rev_1", "Key": base,
        "__children": [{
            "Type": "Key", "Name": f"{serial}&0", "Key": base,
            "__children": [{"Type": "REG_SZ", "Name": "FriendlyName",
                            "Data": f'"{vendor} {product} USB Device"'}],
        }],
    }]


def test_usb_extraction_is_invariant_under_relabeling():
    a = extract_usbstor_from_printkey(_usbstor_printkey("Aaa", "Bbb", "SERIAL_AAAA"))
    b = extract_usbstor_from_printkey(_usbstor_printkey("Xyz", "Qrs", "SERIAL_ZZZZ"))
    # different invented values -> SAME structure; each just echoes its own input
    assert a[0].keys() == b[0].keys()
    assert a[0]["serial"] == "SERIAL_AAAA" and b[0]["serial"] == "SERIAL_ZZZZ"
    assert a[0]["vendor"] == "Aaa" and b[0]["vendor"] == "Xyz"


# ── UserAssist: ROT13 over ANY value name; no program allowlist ───────────
class _V:
    def __init__(self, n, d): self._n = n; self._d = d
    def name(self): return self._n
    def value(self): return self._d


class _K:
    def __init__(self, name, subkeys=None, values=None):
        self._n = name; self._s = subkeys or []; self._v = values or []
    def name(self): return self._n
    def subkeys(self): return self._s
    def values(self): return self._v
    def subkey(self, n):
        for k in self._s:
            if k.name().lower() == n.lower():
                return k
        raise KeyError(n)


class _H:
    def __init__(self, keys): self._k = keys
    def open_key(self, p):
        if p not in self._k:
            raise KeyError(p)
        return self._k[p]


def _ntuser(program):
    import struct
    blob = bytearray(72); blob[4:8] = (3).to_bytes(4, "little")
    count = _K("Count", values=[_V(_rot13(program), bytes(blob))])
    guid = _K("{GUID}", subkeys=[count])
    ua = _K("UserAssist", subkeys=[guid])
    return _H({r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist": ua})


def test_userassist_decodes_any_program_name():
    for prog in ("Totally.Made.Up.App", r"Z:\nonexistent\thing.exe", "x" * 30):
        assert _rot13(_rot13(prog)) == prog                       # decode is value-agnostic
        rows = extract_userassist(_ntuser(prog), user="anyuser")
        assert rows and rows[0]["Name"] == prog                   # extracts whatever is there
