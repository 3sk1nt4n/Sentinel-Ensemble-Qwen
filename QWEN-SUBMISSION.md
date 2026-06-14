# Sentinel Ensemble - Qwen Cloud edition (Track 4: Autopilot Agent)

> An autonomous DFIR / SOC triage agent that turns raw evidence (or an alert)
> into a verified, analyst-ready incident report - running on **Qwen models
> hosted on Alibaba Cloud**, with a deterministic trust layer so the agent never
> reports a finding it cannot prove.

**Hackathon:** Global AI Hackathon with Qwen Cloud
**Track:** 4 - Autopilot Agent
**Repo:** public, MIT (`LICENSE`, visible in About)
**Proof of Alibaba Cloud usage:** [`src/sift_sentinel/llm_provider.py`](src/sift_sentinel/llm_provider.py) - issues live HTTPS calls to the Alibaba Cloud DashScope API.

---

## Why this is a Track-4 Autopilot Agent

Track 4 asks for an agent that "automates real-world business workflows
end-to-end ... from system alerts to automated remediation," handling ambiguous
inputs, invoking external tools, with human-in-the-loop checkpoints, and
production-readiness over toy demos. SOC/DFIR triage is exactly that:

| Track-4 requirement | How Sentinel Ensemble meets it |
|---|---|
| Ambiguous inputs | Raw memory/disk evidence or an alert - the agent profiles it and decides what to investigate |
| Invoke external tools | 195 typed forensic tools (Volatility 3, Sleuth Kit, EZ Tools, Plaso) on a custom MCP server - **zero shell access** |
| Human-in-the-loop checkpoints | The deterministic validator routes unproven claims to a **needs-review** bucket instead of asserting them - the analyst decides |
| End-to-end automation | A 16-step deterministic conductor runs the whole pipeline; the model is invoked only inside well-bounded steps |
| Production-readiness | Read-only evidence + SHA256 chain-of-custody, fail-closed gates, a 4-layer trust pipeline, and an auditable report |

The differentiator is the **anti-hallucination trust layer**: code - not the
model - decides what is "confirmed," and every finding traces to the exact tool
output that proves it (see [`SELF-CORRECTION-PROOF.md`](SELF-CORRECTION-PROOF.md)).

---

## What changed for this hackathon (the significant in-window update)

This project builds on a prior DFIR agent, then was **significantly updated
after the start of the Submission Period (2026-05-26)** for Qwen Cloud, in this
fresh repository:

1. **Pluggable Qwen Cloud provider** - new `src/sift_sentinel/llm_provider.py`:
   a `make_llm_client()` factory + a stdlib DashScope (OpenAI-compatible)
   adapter, duck-typed to the call surface the pipeline already used. The entire
   16-step pipeline now runs on **Qwen models on Alibaba Cloud**, selected purely
   by environment - no model literal is hardcoded.
2. **All four LLM call sites rewired** to the provider factory (coordinator,
   ensemble, ReAct, report) - default provider stays Anthropic so the change is
   zero-regression (proven: identical test-failure set vs the pre-port tree).
3. **Qwen cost model + config** - `pricing.py` Qwen rate rows and a one-file
   `.env.qwen.example` (recommended model tiering for the $40 credit).
4. **Alibaba Cloud deployment** - ECS (forensic toolchain) + OSS (evidence) +
   DashScope (inference). *(in progress)*
5. **Track-4 reframing + documentation** *(in progress)*.

---

## How it runs on Qwen (no code change - env only)

```bash
cp .env.qwen.example .env            # then set DASHSCOPE_API_KEY
# or export directly:
export SIFT_LLM_PROVIDER=qwen
export DASHSCOPE_API_KEY=...         # your Qwen Cloud key ($40 hackathon voucher)
export SIFT_DEFAULT_MODEL=qwen-max   # model_roles.py resolves it

./findevil.sh /path/to/case          # full autonomous investigation on Qwen
```

**Models used** (flagship where reasoning matters; cheaper tier where call
volume is, to fit the $40 credit):

| Stage | Model |
|---|---|
| Keystone analysis, final adjudication (13AA) | `qwen-max` |
| Ensemble members, ReAct cross-check, tool selection, report | `qwen-plus` |
| (optional) multimodal artifact parsing | `qwen-vl-max` |

*(Confirm exact current model IDs in your DashScope model list.)*

---

## Architecture (Qwen Cloud + Alibaba)

```
analyst / alert
      |
      v
 deterministic conductor (run_pipeline.py)  --- owns all 16 steps
      |  reasoning only, inside bounded steps
      v
 Qwen models  <--->  Alibaba Cloud DashScope API   (llm_provider.py)
      |
      v
 typed MCP forensic tools (no shell)  ->  evidence (read-only, OSS)
      |
      v
 4-layer trust gate + 2-layer self-correction (code checks the AI)
      |
      v
 verified, risk-ranked incident report
```

Full design: [`ARCHITECTURE.md`](ARCHITECTURE.md). The conductor invokes the
model only inside marked steps; everything that decides what reaches the report
(validation, calibration, self-correction gating, the report) is deterministic
Python.

---

## Status

| Item | State |
|---|---|
| Qwen/DashScope provider + wiring | done (zero-regression) |
| Qwen config + cost model | done |
| Public repo + MIT license | done |
| Proof-of-Alibaba-Cloud code file | done (`llm_provider.py`) |
| Architecture diagram (Qwen box) | to update |
| Live Qwen run + artifacts | pending `DASHSCOPE_API_KEY` |
| Alibaba ECS deployment + proof recording | pending ECS |
| Demo video (<3 min, YouTube/Vimeo/Youku) | pending live run |

> **Honesty note:** `artifacts/run-rd01/` is the **Claude reference run** that
> proves the architecture end-to-end; it is **not** a Qwen run. No Qwen-specific
> performance numbers are claimed until a live Qwen run replaces it. The
> trust-layer, tool, and pipeline design are model-agnostic and carry over
> unchanged.
