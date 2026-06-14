"""Universal applicability probe: pins the EXACT reason a high-value tool is
no-hit (disk mount unavailable / artifact absent / binary missing), reusing the
same resolvers Step 6 dispatch uses. All synthetic paths -- dataset-agnostic.
"""
from sift_sentinel.runtime.high_value_tool_args import tool_applicability_report


def test_no_evidence_marks_disk_tools_not_applicable_with_reason():
    rep = tool_applicability_report()  # no image, no disk
    assert rep["run_srumecmd"]["status"] == "not_applicable"
    assert "disk mount" in rep["run_srumecmd"]["reason"].lower()
    # every probed tool carries a concrete reason, never blank
    for tool, info in rep.items():
        if info["status"] == "not_applicable":
            assert info["reason"], tool


def test_srum_artifact_absent_reason(tmp_path):
    # a mount that exists but has no SRUDB.dat -> the precise artifact reason
    (tmp_path / "Windows" / "System32").mkdir(parents=True)
    rep = tool_applicability_report(disk_mount=str(tmp_path))
    assert rep["run_srumecmd"]["status"] == "not_applicable"
    assert "SRUDB.dat" in rep["run_srumecmd"]["reason"]


def test_srum_artifact_present_advances_past_artifact_gate(tmp_path):
    # SRUDB.dat present -> NOT the 'disk mount' nor 'not found' reason. On a box
    # without SrumECmd it stops at the binary gate (still a precise reason);
    # with the binary it is applicable. Either way the artifact gate passed.
    sru = tmp_path / "Windows" / "System32" / "sru"
    sru.mkdir(parents=True)
    (sru / "SRUDB.dat").write_bytes(b"\x00")
    rep = tool_applicability_report(disk_mount=str(tmp_path))
    info = rep["run_srumecmd"]
    if info["status"] == "not_applicable":
        assert "binary" in info["reason"].lower()      # only the binary can block now
        assert "not found under" not in info["reason"]  # artifact gate passed
    else:
        assert info["status"] == "applicable"


def test_report_covers_the_whole_high_value_set():
    rep = tool_applicability_report()
    # the probe reports on the full high-value set (srum + the EZ disk tools)
    for t in ("run_srumecmd", "run_amcacheparser", "run_evtxecmd", "run_mftecmd"):
        assert t in rep and rep[t]["status"] in ("applicable", "not_applicable")
