"""Dedup-by-(entity, technique) -- universal, structural keys only (no tool/case
names). Asserts COLLAPSE behavior on the duplicate shapes the live run produced.
"""
from sift_sentinel.analysis.dedup_findings import dedup_key, dedupe_findings

_IFEO = (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
         r"\Image File Execution Options\app.exe\Debugger")
_SAFEBOOT = r"HKLM\System\ControlSet001\Control\SafeBoot\AlternateShell"


def _f(fid, title, **kw):
    d = {"finding_id": fid, "title": title, "claims": []}
    d.update(kw)
    return d


def test_three_ifeo_dupes_collapse_to_one_keeping_best():
    a = _f("F052", "IFEO debugger persistence", description=_IFEO, severity="MEDIUM",
           confidence_level="MEDIUM")
    b = _f("F038", "IFEO debugger hijacking persistence", description=_IFEO,
           severity="MEDIUM")
    c = _f("F023", "IFEO debugger persistence via app", description=_IFEO,
           severity="HIGH", confidence_level="HIGH", deterministic_check="passed",
           malicious_semantic_signals=["ifeo_debugger_hijack"], source_tools=["run_recmd"])
    out, dropped = dedupe_findings([a, b, c])
    fids = {x["finding_id"] for x in out}
    assert dropped == 2 and len(out) == 1
    assert "F023" in fids  # the validated/HIGH/has-signal one survived


def test_three_safeboot_dupes_collapse():
    xs = [_f("F022", "SafeBoot AlternateShell", description=_SAFEBOOT),
          _f("F036", "Safe boot registry persistence", description=_SAFEBOOT),
          _f("F050", "Safe Boot alternate shell persistence", description=_SAFEBOOT)]
    out, dropped = dedupe_findings(xs)
    assert dropped == 2 and len(out) == 1


def test_privilege_cluster_on_same_process_collapses():
    xs = [_f("F032", "Elevated privilege rundll32.exe SeDebugPrivilege"),
          _f("F044", "Elevated privilege context rundll32.exe SeImpersonatePrivilege"),
          _f("F010", "rundll32.exe with SeDebugPrivilege SeLoadDriverPrivilege")]
    out, dropped = dedupe_findings(xs)
    assert dropped == 2 and len(out) == 1


def test_different_technique_same_target_not_merged():
    inj = _f("A", "memory injection PAGE_EXECUTE_READWRITE in proc.exe")
    priv = _f("B", "SeDebugPrivilege on proc.exe")
    out, dropped = dedupe_findings([inj, priv])
    assert dropped == 0 and len(out) == 2  # injection != privilege


def test_no_key_passthrough():
    f = _f("Z", "a vague narrative with no structural anchor")
    assert dedup_key(f) is None
    out, dropped = dedupe_findings([f])
    assert dropped == 0 and out == [f]


def test_dropped_tools_merged_into_representative():
    a = _f("F1", "SafeBoot AlternateShell", description=_SAFEBOOT,
           severity="HIGH", deterministic_check="passed", source_tools=["run_recmd"])
    b = _f("F2", "Safe boot persistence", description=_SAFEBOOT,
           source_tools=["parse_registry_persistence", "get_amcache"])
    out, dropped = dedupe_findings([a, b])
    assert dropped == 1
    rep = out[0]
    assert {"run_recmd", "parse_registry_persistence", "get_amcache"} <= set(rep["source_tools"])
