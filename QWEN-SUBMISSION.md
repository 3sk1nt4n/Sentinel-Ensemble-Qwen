# Sentinel Ensemble - Qwen Cloud edition (Track 4: Autopilot Agent)

> An autonomous DFIR / SOC triage agent that turns raw evidence (or an alert)
> into a verified, analyst-ready incident report - running on **Qwen models
> hosted on Alibaba Cloud**, with a deterministic trust layer so the agent never
> reports a finding it cannot prove.

**Hackathon:** Global AI Hackathon with Qwen Cloud
**Track:** 4 - Autopilot Agent
**Repo:** https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen (public, MIT - `LICENSE` visible in About)
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
| Public repo + MIT license | done (github.com/3sk1nt4n/Sentinel-Ensemble-Qwen) |
| Proof-of-Alibaba-Cloud code file | done (`llm_provider.py`) |
| Architecture diagram (Qwen box) | done (`ARCH_VERTICAL.png`) |
| **Live Qwen run + artifacts** | **done** - see "Verified Qwen Cloud run" below |
| Demo video (<3 min, YouTube/Vimeo/Youku) | built (`docs/sentinel-qwen-demo.mp4`, 1:55, paired run + real dynamic footage) - upload to YouTube + add the link |
| Alibaba ECS deployment + proof recording | optional / pending ECS |
| Legacy-doc reframe to Track 4 | done |

### Verified Qwen Cloud runs (proof)

Two full **paired (memory + disk)** investigations ran end-to-end on **Qwen models
on Alibaba Cloud DashScope** (rd01 Windows case: memory image + C: drive image,
both opened read-only) - the **same deterministic trust layer**, two model tiers.
Both record `llm_provider=qwen`, the DashScope endpoint, and **SHA-256 MATCH on
both images** in `pipeline_summary.json`.

| | Light tier (`qwen-plus` ×4) | **Heavy tier (`qwen3.7-max` everywhere)** |
|---|---|---|
| Models | qwen-plus ensemble + ReAct | qwen3.7-max for Inv1 / Inv2×4 / Inv3A / ReAct / Report |
| Findings (final) | 19 | 25 |
| **Confirmed malicious** | **0** | **4** |
| needs-review / benign / inconclusive | 1 / 1 / 18 | 3 / 5 / 13 |
| Tokens (in / out) | 779,821 / 27,700 | 738,243 / 85,508 |
| Runtime | 6m 22s | 13m 07s |
| Cost | ~$0.35 | ~$2.49 |
| Integrity (mem + disk) | MATCH | MATCH |
| Disposition + 4 confirm gates | PASS | PASS |

**Same gates, different depth.** On the light tier the ensemble's strongest lead -
code injection in `powershell.exe` (PID 8712, RWX private memory) - carried no
atomic proof, so `NO_SPECULATIVE_CONFIRMED_GATE` / `MISSING_RAW_EVIDENCE_CONFIRMED_GATE`
routed it to *inconclusive*: **0 confirmed**. The AI proposed; the code disposed.

On the heavy tier the flagship's deeper analysis surfaced a real, provable
intrusion chain and **4 findings cleared every confirmation gate**:

- **F004 / F012 (CRITICAL)** - `PsExec.exe` / `PSEXESVC.exe` staged and executed from a temp dir (lateral movement)
- **F016 (CRITICAL)** - staged credential-access binaries (credential dumping + lateral movement)
- **F003 (MEDIUM)** - `PWDumpX.exe` executed from a temp dir (credential dumping)

Each traces to its proof tools (`extract_mft_timeline`, `get_amcache`,
`parse_event_logs`, `parse_registry_persistence`, `run_appcompatcacheparser`,
`vol_pstree`). Even at full power the gates still rejected the unproven
(5 benign, 13 inconclusive) - **the trust layer is the constant; the model tier
just changes how much clears the bar.** Dashboards: `docs/qwen_paired_dashboard.png`
(light), `docs/qwen_allmax_dashboard.png` (heavy); demo video `docs/sentinel-qwen-demo.mp4`.

> **Honesty note:** both are real Qwen Cloud runs (numbers straight from
> `pipeline_summary.json`). The light tier's **0 confirmed** is the design working,
> not a gap - no evidence, no confirm. An earlier Claude reference run on the same
> case stays local-only / not shipped (case-neutral policy); the heavy-tier Qwen
> run independently reproduced that intrusion chain. The trust layer, the typed
> forensic tools, and the 16-step conductor are model-agnostic - only the
> provider/tier differs.
