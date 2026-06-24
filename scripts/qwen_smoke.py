#!/usr/bin/env python3
"""Qwen Cloud (Alibaba Cloud / DashScope) connectivity smoke test.

Run this the moment your DASHSCOPE_API_KEY is active to confirm the pipeline's
provider seam reaches Qwen on Alibaba Cloud before a full investigation:

    export SIFT_LLM_PROVIDER=qwen
    export DASHSCOPE_API_KEY=sk-...
    python3 scripts/qwen_smoke.py            # uses SIFT_DEFAULT_MODEL or qwen-plus

It makes ONE tiny chat call through src/sift_sentinel/llm_provider.py (the same
seam the 16-step pipeline uses) and prints the reply + token usage. No evidence,
no pipeline -- just the Alibaba Cloud round-trip.

Exit codes: 0 = reached Qwen; 2 = no key / not configured; 1 = call failed.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))


def main() -> int:
    from sift_sentinel.llm_provider import active_provider, is_qwen, make_llm_client

    provider = active_provider()
    if not is_qwen():
        print(f"SIFT_LLM_PROVIDER={provider!r} (not qwen).")
        print("  Set: export SIFT_LLM_PROVIDER=qwen   then re-run.")
        return 2
    if not (os.environ.get("DASHSCOPE_API_KEY") or os.environ.get("QWEN_API_KEY")):
        print("No DASHSCOPE_API_KEY / QWEN_API_KEY set.")
        print("  Set: export DASHSCOPE_API_KEY=sk-...   then re-run.")
        return 2

    model = os.environ.get("SIFT_DEFAULT_MODEL") or "qwen-plus"
    endpoint = os.environ.get(
        "DASHSCOPE_BASE_URL",
        "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions",
    )
    print(f"Calling Qwen on Alibaba Cloud DashScope ...")
    print(f"  model    : {model}")
    print(f"  endpoint : {endpoint}")
    try:
        resp = make_llm_client().messages.create(
            model=model,
            max_tokens=32,
            temperature=0,
            messages=[{"role": "user",
                       "content": "Reply with exactly: SENTINEL-QWEN-OK"}],
        )
    except Exception as exc:  # noqa: BLE001 -- surface any transport/auth error
        print(f"\n  FAILED: {type(exc).__name__}: {exc}")
        print("  Check the key, the endpoint region, and outbound HTTPS (443).")
        return 1

    text = resp.content[0].text if resp.content else ""
    u = resp.usage
    print("\n  OK -- reached Qwen on Alibaba Cloud.")
    print(f"  reply  : {text.strip()[:80]!r}")
    print(f"  tokens : input={u.input_tokens} output={u.output_tokens}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
