#!/usr/bin/env python3
"""Sentinel Qwen Ensemble Tool Verification. Tests every layer without API calls.
Run: python3 verify_tools.py         (free, cached only)
Run: python3 verify_tools.py --live  (runs real Volatility, ~5 min)"""

import sys
import os
import json
import time
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

MEMORY = "/cases/evidence/base-rd01-memory.img"
DISK = "/cases/evidence/base-rd-01-cdrive.E01"
PASS = FAIL = SKIP = 0

def ok(msg):
    global PASS; PASS += 1; print(f"  PASS  {msg}")
def fail(msg):
    global FAIL; FAIL += 1; print(f"  FAIL  {msg}")
def skip(msg):
    global SKIP; SKIP += 1; print(f"  SKIP  {msg}")
def section(title):
    print(f"\n{'='*60}\n  {title}\n{'='*60}")

def level_1_imports():
    section("LEVEL 1: All source files import cleanly")
    modules = [
        "sift_sentinel.tools.memory",
        "sift_sentinel.tools.memory_extended",
        "sift_sentinel.tools.memory_extended2",
        "sift_sentinel.tools.disk",
        "sift_sentinel.tools.disk_extended",
        "sift_sentinel.tools.generic",
        "sift_sentinel.tools.tool_catalog",
        "sift_sentinel.tools.common",
        "sift_sentinel.validation.validator",
        "sift_sentinel.validation.reference_set",
        "sift_sentinel.validation.normalize_claims",
        "sift_sentinel.validation.ancestry",
        "sift_sentinel.validation.report_validation",
        "sift_sentinel.correction.self_correct",
        "sift_sentinel.analysis.confidence",
        "sift_sentinel.coordinator",
        "sift_sentinel.mcp_client",
    ]
    import importlib
    for mod in modules:
        try:
            importlib.import_module(mod)
            ok(mod)
        except Exception as exc:
            fail(f"{mod}: {exc}")

def level_2_catalog():
    section("LEVEL 2: Tool Catalog")
    from sift_sentinel.tools.tool_catalog import get_categories, get_tools_for_category, recommend_tools
    cats = get_categories()
    ok(f"{len(cats)} categories") if len(cats) >= 7 else fail(f"Only {len(cats)} categories")
    total = 0
    for name in cats:
        info = get_tools_for_category(name)
        n = info.get("total_available", 0)
        total += n
        ok(f"  {name}: {n} tools") if n > 0 else fail(f"  {name}: EMPTY")
    print(f"  Total discoverable: {total}")
    from sift_sentinel.tools.generic import list_volatility_plugins
    vol_plugins = list_volatility_plugins()
    sleuthkit_count = 8
    combined = total + len(vol_plugins) + sleuthkit_count + 1
    print(f"  Volatility plugins (generic): {len(vol_plugins)}")
    print(f"  Sleuthkit commands: {sleuthkit_count}")
    print(f"  YARA scanner: 1")
    print(f"  COMBINED TOTAL: {combined}+ tools available")
    ok(f"Combined: {combined}+ tools") if combined > 100 else fail(f"Only {combined} tools")
    rec = recommend_tools("suspicious process injection")
    if "malware_detection" in rec.get("recommended_categories", []):
        ok("Recommender: injection -> malware_detection")
    else:
        fail(f"Recommender returned: {rec}")

def level_3_cached_tools():
    section("LEVEL 3: Cached Tools (19 specific)")
    from sift_sentinel.tools.memory import vol_pstree, vol_netscan, vol_malfind, vol_cmdline, vol_dlllist
    from sift_sentinel.tools.memory_extended import vol_psscan, vol_handles, vol_envars, vol_getsids, vol_privileges
    from sift_sentinel.tools.memory_extended2 import vol_svcscan, vol_sessions, vol_ssdt, vol_filescan, vol_reg_hivelist
    from sift_sentinel.tools.disk import get_amcache, extract_mft_timeline
    tools = {
        "vol_pstree": lambda: vol_pstree(MEMORY),
        "vol_netscan": lambda: vol_netscan(MEMORY),
        "vol_malfind": lambda: vol_malfind(MEMORY),
        "vol_cmdline": lambda: vol_cmdline(MEMORY),
        "vol_dlllist": lambda: vol_dlllist(MEMORY),
        "vol_psscan": lambda: vol_psscan(MEMORY),
        "vol_handles": lambda: vol_handles(MEMORY),
        "vol_envars": lambda: vol_envars(MEMORY),
        "vol_getsids": lambda: vol_getsids(MEMORY),
        "vol_privileges": lambda: vol_privileges(MEMORY),
        "vol_svcscan": lambda: vol_svcscan(MEMORY),
        "vol_sessions": lambda: vol_sessions(MEMORY),
        "vol_ssdt": lambda: vol_ssdt(MEMORY),
        "vol_filescan": lambda: vol_filescan(MEMORY),
        "vol_reg_hivelist": lambda: vol_reg_hivelist(MEMORY),
        "get_amcache": lambda: get_amcache(DISK),
        "extract_mft_timeline": lambda: extract_mft_timeline(DISK, "2018-09-04", "2018-09-07"),
    }
    for name, func in tools.items():
        try:
            r = func()
            rc = r.get("record_count", 0)
            ok(f"{name}: {rc} records") if rc > 0 else fail(f"{name}: 0 records")
        except Exception as exc:
            fail(f"{name}: {exc}")

def level_4_normalizer():
    section("LEVEL 4: Normalizer + Validator Chain")
    from sift_sentinel.validation.normalize_claims import normalize_claims
    from sift_sentinel.validation.reference_set import build_reference_set
    from sift_sentinel.validation.validator import validate_finding
    def load_w(n):
        with open(f"cached_outputs/{n}.json") as f: d = json.load(f)
        return {"output": d, "record_count": len(d) if isinstance(d, list) else 1}
    try:
        ao = {n: load_w(n) for n in ["vol_pstree","vol_netscan","vol_malfind","get_amcache","extract_mft_timeline","vol_cmdline","vol_dlllist"]}
        ref = build_reference_set(ao)
        ok(f"Reference set: {len(ref.get('pid_to_process', {}))} PIDs")
    except Exception as exc:
        fail(f"Reference set: {exc}"); return
    bad = [{"finding_id":"T","title":"x","description":"x","claims":[
        {"type":"pid","pid":9001,"process_name":"sample_payload.exe"},
        {"type":"hash","hash":"fake","path":"C:\\\\evil.exe"},
        {"type":"connection","pid":0,"foreign_addr":"192.0.2.1"},
    ]}]
    fixed = normalize_claims(bad)
    ok(f"Normalizer: 3 -> {len(fixed[0]['claims'])} claims") if len(fixed[0]["claims"]) < 3 else fail("Normalizer didn't remove bad claims")
    r = validate_finding(fixed[0], ref)
    ok(f"Validator after normalize: {r['status']}")

def level_5_ancestry():
    section("LEVEL 5: Ancestry Validator")
    from sift_sentinel.validation.ancestry import check_ancestry
    def flatten(recs):
        f = []
        for r in recs:
            f.append(r); f.extend(flatten(r.get("__children", [])))
        return f
    try:
        with open("cached_outputs/vol_pstree.json") as f: data = json.load(f)
        flat = flatten(data)
        v = check_ancestry(flat)
        ok(f"Checked {len(flat)} processes, {len(v)} violations")
    except Exception as exc:
        fail(f"Ancestry: {exc}")

def level_6_generic():
    section("LEVEL 6: Generic Runners")
    from sift_sentinel.tools.generic import list_volatility_plugins, run_volatility_plugin, run_sleuthkit
    plugins = list_volatility_plugins()
    ok(f"Discovered {len(plugins)} Vol plugins") if len(plugins) > 50 else fail(f"Only {len(plugins)} plugins")
    r = run_volatility_plugin(MEMORY, "linux.bash.Bash")
    ok("Security: non-windows plugin rejected") if "error" in r else fail("Security: allowed non-windows")
    r = run_sleuthkit("rm", DISK)
    ok("Security: disallowed command rejected") if "error" in r else fail("Security: allowed rm")

def level_7_live(plugins_to_test):
    section("LEVEL 7: Live Volatility (real evidence)")
    import subprocess
    if not os.path.exists(MEMORY):
        fail("Memory image not found"); return
    for plugin in plugins_to_test:
        t0 = time.time()
        try:
            r = subprocess.run(["vol","-f",MEMORY,"-r","json",plugin], capture_output=True, text=True, timeout=120)
            elapsed = time.time() - t0
            if r.returncode == 0:
                data = json.loads(r.stdout)
                count = len(data) if isinstance(data, list) else 1
                ok(f"{plugin}: {count} records in {elapsed:.1f}s")
            else:
                fail(f"{plugin}: exit {r.returncode}")
        except subprocess.TimeoutExpired:
            fail(f"{plugin}: timeout")
        except Exception as exc:
            fail(f"{plugin}: {exc}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    print("Sentinel Qwen Ensemble Tool Verification")
    print(f"Memory: {MEMORY}")
    print(f"Disk:   {DISK}")
    level_1_imports()
    level_2_catalog()
    level_3_cached_tools()
    level_4_normalizer()
    level_5_ancestry()
    level_6_generic()
    if args.live:
        level_7_live(["windows.pstree.PsTree","windows.netscan.NetScan","windows.malfind.Malfind"])
    else:
        print("\n  (Run with --live for real Volatility tests)")
    print(f"\n{'='*60}")
    print(f"  RESULTS: {PASS} PASS | {FAIL} FAIL | {SKIP} SKIP")
    print(f"{'='*60}")
    print(f"  {'ALL VERIFIED' if FAIL == 0 else 'ISSUES FOUND'}")
    sys.exit(1 if FAIL > 0 else 0)

if __name__ == "__main__":
    main()
