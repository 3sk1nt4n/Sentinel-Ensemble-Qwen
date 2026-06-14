"""One-shot: generate vol_help_cache.json from `vol <plugin> --help` output.

Run once. Cache is committed to repo. Server loads this at import time
instead of running 135 subprocesses at startup.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def extract_first_description(help_output: str) -> str:
    """Extract the first descriptive line from vol --help output."""
    lines = [ln.strip() for ln in help_output.split("\n") if ln.strip()]
    for ln in lines:
        if ln.startswith("usage:"):
            continue
        if ln.startswith("options:") or ln.startswith("-h,"):
            break
        if ln.startswith("-") or ln.startswith("["):
            continue
        if len(ln) > 10:
            return ln
    return ""


def main() -> int:
    from sift_sentinel.tools.common import VOLATILITY_PLUGINS

    cache = {}
    total = len(VOLATILITY_PLUGINS)
    for i, (key, plugin) in enumerate(sorted(VOLATILITY_PLUGINS.items()), 1):
        try:
            r = subprocess.run(
                ["vol", plugin, "--help"],
                capture_output=True, text=True, timeout=15,
            )
            desc = extract_first_description(r.stdout)
            cache[key] = {"plugin": plugin, "description": desc}
            print(f"[{i:3d}/{total}] {key}: {desc[:60]}")
        except subprocess.TimeoutExpired:
            cache[key] = {"plugin": plugin, "description": "(help timeout)"}
        except Exception as e:
            cache[key] = {"plugin": plugin, "description": f"(error: {e})"}

    out_path = Path("src/vol_help_cache.json")
    out_path.write_text(json.dumps(cache, indent=2, sort_keys=True))
    print(f"\nWrote {len(cache)} entries to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
