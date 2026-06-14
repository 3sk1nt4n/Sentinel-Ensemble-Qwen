"""Memory-only confidence: a textbook injection corroborated by 3+ INDEPENDENT memory
lenses (RWX region + unbacked module + injected thread ...) reaches HIGH, the within-
domain equivalent of cross-domain confirmation. Gated strictly to a memory-only run so
PAIRED / disk-only runs are byte-identical; requires SSDT trust 'full'; correlated views
of the same structure cannot fake independence. Universal: method-independence, no case
data.
"""
from sift_sentinel.analysis.confidence import (
    calibrate_confidence as cc, count_memory_lenses as ml,
)

INJ = ["vol_malfind", "vol_ldrmodules", "vol_suspiciousthreads"]  # vad + mod + thread


def _f(tools, conf="MEDIUM", **kw):
    return {"finding_id": "X", "confidence_level": conf, "source_tools": list(tools), "claims": [], **kw}


def test_three_independent_lenses_counts_three():
    assert ml(INJ) == 3
    assert ml(["vol_malfind", "vol_vadinfo", "vol_vadyarascan"]) == 1   # all VAD-region
    assert ml(["vol_ldrmodules", "vol_dlllist", "vol_malfind"]) == 2     # mod+mod+vad


def test_memory_only_injection_upgrades_to_high():
    assert cc(_f(INJ, "MEDIUM"), run_domain="memory") == "HIGH"


def test_paired_and_default_are_unchanged():
    assert cc(_f(INJ, "MEDIUM"), run_domain="paired") == "MEDIUM"
    assert cc(_f(INJ, "MEDIUM"), run_domain=None) == "MEDIUM"      # no env -> no boost
    assert cc(_f(INJ, "MEDIUM"), run_domain="disk") == "MEDIUM"


def test_redundant_views_cannot_fake_independence():
    assert cc(_f(["vol_malfind", "vol_vadinfo", "vol_vadyarascan"], "MEDIUM"), run_domain="memory") == "MEDIUM"
    assert cc(_f(["vol_ldrmodules", "vol_dlllist", "vol_malfind"], "MEDIUM"), run_domain="memory") == "MEDIUM"
    assert cc(_f(["vol_malfind", "vol_ldrmodules"], "MEDIUM"), run_domain="memory") == "MEDIUM"  # 2 lenses


def test_ssdt_untrusted_blocks_the_memory_upgrade():
    assert cc(_f(INJ, "MEDIUM"), ssdt_trust="partial", run_domain="memory") == "MEDIUM"


def test_fp_marker_still_forces_low():
    f = _f(INJ); f["react_conclusion"] = {"is_false_positive": True}
    assert cc(f, run_domain="memory") == "LOW"


def test_disk_only_unaffected_reaches_high_via_types():
    assert cc(_f(["get_amcache", "parse_registry", "parse_event_logs"], "HIGH"), run_domain="disk") == "HIGH"


def test_env_drives_when_param_absent(monkeypatch):
    monkeypatch.setenv("SIFT_RUN_DOMAIN", "memory")
    assert cc(_f(INJ, "MEDIUM")) == "HIGH"
    monkeypatch.setenv("SIFT_RUN_DOMAIN", "paired")
    assert cc(_f(INJ, "MEDIUM")) == "MEDIUM"
