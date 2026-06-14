#!/usr/bin/env python3
"""Evidence-speaks policy audit.

This audit blocks:
- degraded-memory tool blacklists
- known-empty / known-broken skip-sheet language
- non-empty LOW_YIELD_TOOLS skip registry
- hardcoded tool names inside degraded_memory_signal
- capability schema regressions
- intent registries referencing unregistered tools, if intents exist

It intentionally does NOT contain benchmark IOCs or expected-answer strings.
Optional local forbidden tokens may be placed in:
  audit/forbidden_tokens.local.txt

That file must remain gitignored.
"""

from __future__ import annotations

import importlib
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

sys.path.insert(0, str(SRC))


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    raise SystemExit(1)


def ok(msg: str) -> None:
    print(f"PASS: {msg}")


def read(path: str) -> str:
    return (ROOT / path).read_text(errors="ignore")


def _iter_python_files_for_policy_scan() -> list[Path]:
    roots = [
        ROOT / "run_pipeline.py",
        ROOT / "src" / "sift_sentinel",
        ROOT / "tests",
    ]

    files: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            files.append(root)
        else:
            files.extend(root.rglob("*.py"))

    # Do not scan this audit file itself; it necessarily contains the
    # forbidden phrases as policy tokens.
    return [
        path
        for path in files
        if path.resolve() != Path(__file__).resolve()
    ]


def audit_forbidden_prompt_language() -> None:
    forbidden_phrases = [
        "AVOID these known-broken",
        "PREFER disk-based categories",
        "MORE reliable than memory",
        "known empty",
        "known-broken",
        "known broken",
        "known-zero",
        "known zero",
        "returns 0 records on tested evidence",
        "this evidence contains",
        "ground truth contains",
        "PDF says",
        "DEGRADED-broken",
        "_DEGRADED_BROKEN subtraction",
        "avoid wasting AI turns",
        "known to return zero records",
        "/home/sansforensics/sift-sentinel",
    ]

    scan_roots = [
        ROOT / "run_pipeline.py",
        ROOT / "src" / "sift_sentinel",
        ROOT / "tests",
    ]

    hits: list[str] = []
    audit_file = Path(__file__).resolve()

    for root in scan_roots:
        if not root.exists():
            continue
        files = [root] if root.is_file() else list(root.rglob("*.py"))
        for path in files:
            if path.resolve() == audit_file:
                continue
            text = path.read_text(errors="ignore")
            rel = path.relative_to(ROOT)
            for phrase in forbidden_phrases:
                if phrase.lower() in text.lower():
                    hits.append(f"{rel}: forbidden phrase {phrase!r}")

    if hits:
        fail("\n".join(hits))

    ok("no forbidden cheat-sheet prompt/source/test language")

def audit_local_forbidden_tokens() -> None:
    token_file = ROOT / "audit" / "forbidden_tokens.local.txt"
    if not token_file.exists():
        ok("no local forbidden-token file present")
        return

    tokens = [
        line.strip()
        for line in token_file.read_text(errors="ignore").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not tokens:
        ok("local forbidden-token file empty")
        return

    scan_roots = [
        ROOT / "run_pipeline.py",
        ROOT / "src" / "sift_sentinel",
        ROOT / "tests",
    ]

    hits: list[str] = []
    for root in scan_roots:
        files = [root] if root.is_file() else list(root.rglob("*.py"))
        for path in files:
            text = path.read_text(errors="ignore")
            for token in tokens:
                if token in text:
                    hits.append(f"{path.relative_to(ROOT)} contains local forbidden token")

    if hits:
        fail("\n".join(hits))

    ok("local forbidden tokens absent from repo source")


def audit_low_yield_empty() -> None:
    from sift_sentinel.coordinator import (
        LOW_YIELD_TOOLS,
        _DEGRADED_BROKEN_TOOLS,
    )

    if LOW_YIELD_TOOLS != {}:
        fail(f"LOW_YIELD_TOOLS must be empty, got: {LOW_YIELD_TOOLS!r}")

    if _DEGRADED_BROKEN_TOOLS != frozenset():
        fail(
            "_DEGRADED_BROKEN_TOOLS must be empty; degraded memory may not "
            f"blacklist tools, got: {_DEGRADED_BROKEN_TOOLS!r}"
        )

    ok("LOW_YIELD_TOOLS and _DEGRADED_BROKEN_TOOLS are empty")


def audit_degraded_signal_generic() -> None:
    from sift_sentinel.coordinator import build_inv1_prompt

    with tempfile.TemporaryDirectory() as d:
        prompt = build_inv1_prompt({}, Path(d), degraded_profile=True).read_text()

    match = re.search(
        r"<degraded_memory_signal>(.*?)</degraded_memory_signal>",
        prompt,
        re.DOTALL,
    )
    if not match:
        fail("degraded_memory_signal block missing")

    signal = match.group(1)

    tool_names = re.findall(
        r"\b(?:vol_|run_|parse_|get_|extract_|sleuthkit_)\w+\b",
        signal,
    )
    if tool_names:
        fail(f"hardcoded tool names inside degraded signal: {tool_names}")

    for phrase in [
        "AVOID these known-broken",
        "PREFER disk-based categories",
        "MORE reliable than memory",
    ]:
        if phrase in prompt:
            fail(f"old degraded cheat phrase remains: {phrase!r}")

    ok("degraded memory signal is generic")


def audit_capability_schema() -> None:
    from sift_sentinel.tools.capabilities import _cap

    cap = _cap(
        produces=["records"],
        applicable_when=[],
        not_applicable_when=[],
        failure_modes=[],
        runtime_class="fast",
    )

    for key in [
        "mitre_techniques",
        "kill_chain_phases",
        "behavioral_signals",
    ]:
        if key not in cap:
            fail(f"capability missing field: {key}")
        if cap[key] != ():
            fail(f"default {key} must be empty tuple, got {cap[key]!r}")

    ok("capability schema has additive semantic fields")


def audit_intents_if_present() -> None:
    try:
        intents_mod = importlib.import_module("sift_sentinel.intents")
    except ModuleNotFoundError:
        ok("no intents module yet")
        return

    from sift_sentinel.coordinator import _TOOL_REGISTRY

    intents = getattr(intents_mod, "INVESTIGATION_INTENTS", None)
    if not isinstance(intents, dict):
        fail("sift_sentinel.intents exists but INVESTIGATION_INTENTS is not a dict")

    missing: dict[str, list[str]] = {}
    for intent_name, spec in intents.items():
        tools = spec.get("tools", ())
        for tool in tools:
            if tool not in _TOOL_REGISTRY:
                missing.setdefault(intent_name, []).append(tool)

        if "high_value_indicators" in spec:
            fail(
                f"{intent_name}: high_value_indicators is banned; "
                "use key_techniques / behavioral_signals instead"
            )

        if "cross_validation" in spec and isinstance(spec["cross_validation"], str):
            fail(
                f"{intent_name}: cross_validation must be structured, not free text"
            )

    if missing:
        fail(f"intent references unregistered tools: {missing}")

    ok("intent registry references only registered tools")


def main() -> None:
    audit_forbidden_prompt_language()
    audit_local_forbidden_tokens()
    audit_low_yield_empty()
    audit_degraded_signal_generic()
    audit_capability_schema()
    audit_intents_if_present()
    print("NO_CHEAT_AUDIT_PASS")


if __name__ == "__main__":
    main()

# NOTE: case-specific benchmark IOCs (attacker IPs / hostnames / hashes / sample
# tool names) are deliberately NOT committed in this file. Shipping them would
# put the evaluation answer key in a public repo and contradicts this file's
# contract (see module docstring). Enforcement lives in the gitignored
# audit/forbidden_tokens.local.txt, scanned by audit_local_forbidden_tokens()
# above: populate it one-token-per-line on the dev box and the gate fails any
# commit / live-run that hardcodes an eval literal into pipeline or detector
# source. A prior revision pasted the rd-01 IOC list here as dead code (defined
# after main(), never scanned) -- both unenforced AND a leak; removed.

