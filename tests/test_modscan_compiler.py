"""vol_modscan -> kernel_module_fact: the light, high-value rootkit-driver
detector that fills the slot freed by the big-memory gate dropping
vol_hollowprocesses.

modscan enumerates ALL kernel modules (incl. unlinked/hidden ones a clean
PsActiveProcessHead walk misses). A .sys loaded from OUTSIDE System32\\drivers
is the kernel-rootkit loading primitive -- the fact carries the module Path into
image_path so the EXISTING conclusive match_kernel_driver_nonstandard_path
detector fires from MEMORY (not just registry/event evidence).

Structural pass-through (like _c_callbacks/_c_ssdt): no module name lists, no
is_malicious judgment. Schema verified against the installed Vol3 modscan plugin
(Offset/Base/Size/Name/Path/File output).
"""
from sift_sentinel.analysis.phase2_extractors import (
    PHASE2_COMPILERS,
    PHASE2_FACT_TYPES,
    _c_modscan,
)
from sift_sentinel.analysis.malicious_semantics import (
    match_kernel_driver_nonstandard_path,
)


def _compile(recs):
    return [f for _i, f, _r in _c_modscan(recs) if f]


def test_registered_and_merged():
    assert PHASE2_COMPILERS.get("vol_modscan") is _c_modscan
    assert "kernel_module_fact" in PHASE2_FACT_TYPES
    from sift_sentinel.analysis.evidence_db import _TOOL_COMPILERS
    assert "vol_modscan" in _TOOL_COMPILERS


def test_real_schema_passthrough():
    rec = {"Offset": "0x1", "Base": "0xfffff80000", "Size": "0x9000",
           "Name": "tcpip.sys",
           "Path": "\\SystemRoot\\System32\\drivers\\tcpip.sys",
           "File output": "Disabled"}
    f = _compile([rec])[0]
    assert f["fact_type"] == "kernel_module_fact"
    assert f["module_name"] == "tcpip.sys"
    assert f["image_path"].endswith("tcpip.sys")
    assert f["index"]["by_path"]            # joinable


def test_nonstandard_sys_fires_conclusive_rootkit_detector():
    # a .sys outside System32\drivers has no benign explanation = rootkit driver
    f = _compile([{"Name": "evil.sys", "Path": "\\??\\C:\\windows\\evil.sys"}])[0]
    assert match_kernel_driver_nonstandard_path(f) is True


def test_legit_system_driver_does_not_fire():
    f = _compile([{"Name": "tcpip.sys",
                   "Path": "\\SystemRoot\\System32\\drivers\\tcpip.sys"}])[0]
    assert match_kernel_driver_nonstandard_path(f) is False


def test_core_kernel_module_does_not_fire():
    f = _compile([{"Name": "ntoskrnl.exe",
                   "Path": "\\SystemRoot\\system32\\ntoskrnl.exe"}])[0]
    assert match_kernel_driver_nonstandard_path(f) is False


def test_metamorphic_random_tokens_passthrough():
    f = _compile([{"Name": "Zq9xK.sys", "Path": "\\x\\y\\Zq9xK.sys"}])[0]
    assert f["module_name"] == "Zq9xK.sys"
    assert f["module_path"] == "\\x\\y\\Zq9xK.sys"


def test_empty_and_malformed():
    assert _compile([]) == []
    assert _compile(None) == []
    reasons = [r for _i, f, r in _c_modscan(["not-a-dict", {"Offset": "0x0"}]) if f is None]
    assert "non_dict_record" in reasons and "no_name_or_path" in reasons
