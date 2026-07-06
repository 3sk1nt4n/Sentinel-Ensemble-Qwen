# Sentinel Ensemble - Qwen Cloud edition (Track 4: Autopilot Agent)

> **Autonomous Digital Forensics & Incident Response / Security Operations
> Center (DFIR/SOC) triage agent on Qwen Cloud (Alibaba DashScope) - Track 4
> Autopilot Agent. Deterministic trust layer: code, not the LLM model, decides
> what is confirmed.** It turns the raw evidence behind an alert into a
> verified, analyst-ready incident report - the agent never reports a finding
> it cannot prove.

**Hackathon:** Global AI Hackathon with Qwen Cloud
**Track:** 4 - Autopilot Agent
**Repo:** https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen (public, MIT - `LICENSE` visible in About)
**Proof of Alibaba Cloud usage:** [`src/sift_sentinel/llm_provider.py`](src/sift_sentinel/llm_provider.py) - issues live HTTPS calls to the Alibaba Cloud DashScope API.

## Where it sits in a SOC (the business case)

An alert fires. Evidence gets captured (memory, disk). Then the expensive part
begins: a trained analyst spends hours - often a full shift - reconstructing
what actually happened, and a hallucinated AI "finding" is worse than no answer,
because a false attribution in an incident report burns response hours and
credibility. Sentinel Ensemble runs that entire triage autonomously in **5-20
minutes for $0.28-$1.53 per full paired investigation** (measured; both runs
shipped in [`docs/qwen-runs/`](docs/qwen-runs/)), refuses to confirm anything it
cannot prove from tool output, and gives the analyst an approve/override
checkpoint before the report. **Incident-response agents fix outages; Sentinel
Ensemble investigates compromises.** The analyst's hours move from evidence
grinding to decision-making.

**Path to production and adoption:** the productization route is a hosted triage
service on Alibaba Cloud (ECS compute + OSS evidence intake + DashScope
inference - the runbook already exists in [`DEPLOY-ALIBABA.md`](DEPLOY-ALIBABA.md)),
priced per investigation against the measured $0.28-$1.53 unit cost. The
open-source route is already live: MIT-licensed, running in Docker on any OS
(one `./setup.sh` command; the image bundles the entire forensic
toolchain), with a documented tool-plugin contract
([`EXTENDING.md`](EXTENDING.md)) so the community can add parsers without
touching the trust layer.

---

## Proof of Deployment on Alibaba Cloud

Per the Devpost x Qwen Cloud rules, proof has two parts:

1. **Code file with the Qwen Cloud Base URL.**
   [`src/sift_sentinel/llm_provider.py`](src/sift_sentinel/llm_provider.py)
   hardcodes the DashScope base URL judges look for and issues the live HTTPS
   calls:
   `https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions`.
   The shipped run-metric files in [`docs/qwen-runs/`](docs/qwen-runs/) (light,
   heavy, plus a July repro and a flags-off ablation) each
   record that same `llm_endpoint`, `llm_provider: qwen`, and the model
   (`qwen3.7-max` / `qwen-plus`) - so the runs demonstrably went to Alibaba Cloud.

2. **Screenshot of running resources on Alibaba Cloud - captured (2026-07-06).**
   The Workbench screenshot is committed at [`docs/proof/`](docs/proof/): a
   **Simple Application Server instance ("Ubuntu-ivhq", Singapore) in the
   *Running* state**, matching the official guide's sample screenshots. The
   backend was deployed on that instance per
   [`DEPLOY-ALIBABA.md`](DEPLOY-ALIBABA.md) (`./setup.sh docker` demo end-to-end
   plus a live `scripts/qwen_smoke.py` call from the instance -
   `SENTINEL-QWEN-OK`), and the instance stays running through the judging
   period for live verification.

---

## Why this is a Track-4 Autopilot Agent

Track 4 asks for an agent that "automates real-world business workflows
end-to-end ... from system alerts to automated remediation," handling ambiguous
inputs, invoking external tools, with human-in-the-loop checkpoints, and
production-readiness over toy demos. SOC/DFIR triage is exactly that:

| Track-4 requirement | How Sentinel Ensemble meets it | Where (code / artifact) |
|---|---|---|
| Ambiguous inputs | Raw memory/disk evidence, exactly as captured behind an alert - the onboarding engine auto-detects memory-only / disk-only / paired, mounts read-only, profiles the OS, and decides what to investigate | `src/sift_sentinel/onboard/`, Inv1 tool selection |
| Invoke external tools | **195 typed forensic tools** (Volatility 3, Sleuth Kit, EZ Tools, Plaso, bulk_extractor, RegRipper, YARA) on a custom **MCP server - zero shell access** | `src/server.py`, `src/sift_sentinel/tools/` |
| Human-in-the-loop **at critical decision points** | Two layers: (1) the deterministic disposition **escalates** unproven claims to a *needs-review* bucket instead of asserting them; (2) an **opt-in approval gate** (`SIFT_HITL_CHECKPOINT=1`) **pauses at the disposition decision - before the report -** for the analyst to **approve or override** any finding's verdict; plus the launch checkpoints (evidence / depth / key) | `src/sift_sentinel/hitl_checkpoint.py`, `analysis/disposition.py`, `step0_onboard.py` |
| End-to-end automation | A **16-step deterministic conductor** runs the whole pipeline with zero steering; the model is invoked only inside bounded steps | `run_pipeline.py` |
| Production-readiness (not a toy) | Read-only evidence + **SHA-256 chain of custody**, ~13 fail-closed gates, automatic prompt caching, a green **4,700+ passing** test suite (`pytest tests/` is green by default; legacy quarantine documented in `tests/QUARANTINE.md`), two real Qwen-Cloud runs, Docker (demo/full/full-plus) | `analysis/`, `tests/`, `Dockerfile` |

**Read-only by design is a feature, not a gap.** Track-4's examples mention
"automated remediation," but in high-stakes incident response, auto-acting on a
live host is exactly the failure mode to avoid. Sentinel Ensemble keeps a
**SHA-256 chain of custody** and **gates remediation behind the human**: it runs
the full triage autonomously, then hands the analyst a proof-linked report and -
with the checkpoint enabled - an explicit approve/override gate. **The agent
automates the judgement; the human authorises the action.**

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
   ensemble, ReAct, report). The seam's bare-env fallback stays Anthropic so the
   port is provably zero-regression (identical test results vs the pre-port
   tree); **every shipped launch path defaults to Qwen** - the Docker image,
   `./setup.sh`, and `.env.qwen.example` all set the provider.
3. **Qwen cost model + config** - `pricing.py` Qwen rate rows and a one-file
   `.env.qwen.example` (recommended model tiering for the $40 credit).
4. **Alibaba Cloud inference (satisfied)** - the reasoning backend runs on the
   Alibaba Cloud DashScope API (`llm_provider.py`); both shipped runs record the
   live DashScope endpoint. Optional ECS hosting + OSS evidence is a turnkey
   runbook in [`DEPLOY-ALIBABA.md`](DEPLOY-ALIBABA.md) (see "Proof of Deployment"
   below).
5. **Track-4 reframing + documentation (done)** - README, this doc, and
   `JUDGE-QUICKSTART.md` map each Track-4 element to the implementation.

---

## How it runs on Qwen (no code change - env only)

```bash
cp .env.qwen.example .env            # then set DASHSCOPE_API_KEY
# or export directly:
export SIFT_LLM_PROVIDER=qwen
export DASHSCOPE_API_KEY=...            # your Qwen Cloud key ($40 hackathon voucher)
export SIFT_DEFAULT_MODEL=qwen3.7-max   # model_roles.py resolves it (flagship)

./setup.sh /path/to/case             # full autonomous investigation on Qwen
                                     # (Docker, any OS - one line builds the image,
                                     #  forwards these envs, mounts evidence read-only)
```

**Models used** (flagship where reasoning matters; cheaper tier where call
volume is, to fit the $40 credit):

| Stage | Model |
|---|---|
| Keystone analysis, final adjudication (13AA) | `qwen3.7-max` |
| Ensemble members, ReAct cross-check, tool selection, report | `qwen-plus` |
| (optional, not wired by default) multimodal artifact parsing | `qwen3.7-plus` (Text + Vision per the official catalog; `qwen-vl-max` legacy alias) |

*(Model IDs are current as of the run date; `qwen3.7-max` is Alibaba's 2026
flagship - the official hackathon FAQ names it for "hyper-complex logic
patterns". `qwen-plus` is the stable alias the shipped run metrics record; the
current marketplace also lists it as `qwen3.7-plus` (balanced) alongside
`qwen3.6-flash` (fast/cost-optimized). Confirm exact IDs in your DashScope
model list.)*

---

## Qwen-specific engineering (not just a provider swap)

Four pieces of DashScope-specific engineering, all exercised by the live runs:

- **Automatic prompt-cache accounting** - DashScope's implicit prefix caching is
  read from `usage.prompt_tokens_details.cached_tokens`, clamped to the prompt
  size, and credited as cache-read in the cost model
  ([`llm_provider.py`](src/sift_sentinel/llm_provider.py)). The heavy run reused
  **381,696 tokens** on the shared ensemble / ReAct / 13AA prefix (~36% cost
  cut, est. at the configured cache rate).
- **`reasoning_content` fallback** - Qwen thinking-mode responses that return an
  empty `content` are recovered from `reasoning_content`, so deep-reasoning
  tiers never silently zero out.
- **Per-model output-cap clamp** - DashScope returns 400 when `max_tokens`
  exceeds a model's output ceiling; the client clamps to
  `SIFT_MAX_OUTPUT_TOKENS` so ensemble members never die on a cap mismatch.
- **Read-timeout resilience** - the all-`qwen3.7-max` ensemble initially died on
  socket read timeouts mid-generation (reasoning calls routinely exceed 120s);
  bounded retries honoring `Retry-After` plus explicit bare-`TimeoutError`
  handling fixed the live run (`SIFT_HTTP_TIMEOUT`; `.env.qwen.example` and every
  documented run command set 600 s - the bare code default is 120 s).

**And a designed model-tier A/B, not two lucky runs:** the light (`qwen-plus` ×4) vs
heavy (`qwen3.7-max`) pair holds the deterministic trust layer constant and
varies only the Qwen model tier - measuring what each tier can *prove*, not
what it says. Result: **0 vs 4 confirmed**. The bar does not move; the model's
ability to clear it does.

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
| **Live Qwen runs + artifacts** | **done** - see "Verified Qwen Cloud runs" below |
| Demo video (<3 min, YouTube) | **done** - https://youtu.be/NV6Zn0YrD1w (2:56, Public); in-repo copy: `docs/sentinel-qwen-demo.mp4`. Run footage shows the engine's former name, "SIFT Sentinel" |
| Proof of Deployment on Alibaba Cloud | **done** - code-file + Base URL (`llm_provider.py`; endpoint also in `docs/qwen-runs/`) **and** the Workbench screenshot in `docs/proof/` (SAS instance Running, Singapore; deployed per `DEPLOY-ALIBABA.md`, live `SENTINEL-QWEN-OK` smoke call; instance stays up through judging) |
| Legacy-doc reframe to Track 4 | done |

### Verified Qwen Cloud runs (proof)

Two full **paired (memory + disk)** investigations ran end-to-end on **Qwen models
on Alibaba Cloud DashScope** (rd01 Windows case: memory + C: drive image, both
read-only), through the **full trust-layer pipeline** (Step-13AA finalize +
review-all, cross-bucket dedup, signature reconcile, baseline gate) - the same
deterministic layer, two model tiers. Both record `llm_provider=qwen`, the live
DashScope endpoint, and **SHA-256 MATCH on both images**; the sanitized aggregate
metrics are shipped in [`docs/qwen-runs/`](docs/qwen-runs/) (full run outputs stay
uncommitted per the case-neutral policy).

| | Light tier (`qwen-plus` ×4) | **Heavy tier (`qwen3.7-max` everywhere)** |
|---|---|---|
| Findings (final) | 11 | 34 |
| **Confirmed malicious** | **0** | **4** |
| needs-review / benign / inconclusive | 9 / 1 / 1 | 21 / 9 / **0** |
| Tokens (uncached in / out) | 614,336 / 23,668 | 306,727 / 89,451 |
| Prompt-cache reuse (cache-read) | 32,512 | **381,696** |
| Runtime | 5m 37s | 14m 44s |
| Cost (cache-aware) | ~$0.28 | ~$1.53 |
| Integrity (mem + disk) | MATCH | MATCH |
| Disposition gate (shipped JSON) + 4 confirm sub-gates (run logs) | PASS | PASS |

**13AA gives a final verdict on everything.** Step-13AA (inv3a) review-all
re-judges every ambiguous finding to a final TP / FP / needs-review disposition,
so the heavy run leaves **zero inconclusive** (it reclassified 22 of the
36-candidate ambiguous set per the run log - the shipped JSON records the
36 → 34 counts and `inconclusive_unresolved = 0` - reconciling to 34 findings
after dedup; a proven-evil floor keeps confirmed findings in the table regardless of
the model's verdict). The light tier's 13AA still confirmed **nothing** - no
atomic proof, no confirm.

**Same gates, different depth.** On the light tier the ensemble's strongest lead -
RWX code injection in `powershell.exe` - never cleared the atomic-proof
bar: **0 confirmed**. The AI proposed; the code disposed. On the heavy tier the
flagship reconstructed a real intrusion chain and **4 findings cleared every
confirmation gate**:

- **F009 (CRITICAL)** - `PsExec.exe` - lateral movement
- **F005 (CRITICAL)** - `PWDumpX.exe` staged - credential dumping
- **F016 (HIGH)** - IFEO `sethc.exe` debugger - sticky-keys backdoor persistence
- **F004 (HIGH)** - `p.exe` executed from a temp directory

Each traces to its proof tools (`extract_mft_timeline`, `get_amcache`,
`parse_event_logs`, `run_appcompatcacheparser`, `vol_pstree`). **Automatic
DashScope prompt caching** reused 381,696 tokens on the heavy run (the shared
ensemble / ReAct / 13AA prefix), cutting its cost ~36%. **The trust layer is the
constant; the model tier just changes how much clears the bar.** Dashboards:
`docs/qwen_paired_dashboard.png` (light), `docs/qwen_allmax_dashboard.png` (heavy)
- their headers read "SIFT Sentinel", the engine's pre-rebrand report title;
demo video `docs/sentinel-qwen-demo.mp4`.

**Reproduced, and ablated (2026-07-01).** An independent rerun on the same case
re-confirmed the intrusion chain (0 inconclusive, integrity MATCH, gate PASS;
3 confirmed - one fewer than June's 4, normal model non-determinism). More
importantly, we ran the **same case, same `qwen3.7-max`, with the trust-layer
finalization flags turned OFF**: findings left inconclusive jumped **0 -> 11**
and confirmations fell **3 -> 1**. That is the trust layer's job made measurable:
it **resolves uncertainty without ever manufacturing a confirmation** - every
promotion in both runs still passed the identical deterministic eligibility gate.
Both are shipped in [`docs/qwen-runs/`](docs/qwen-runs/) (repro + ablation).

> **Honesty note:** both are real Qwen Cloud runs (numbers straight from each
> run's summary JSON; sanitized aggregates shipped in
> [`docs/qwen-runs/`](docs/qwen-runs/)). The light tier's **0 confirmed** is the design working,
> not a gap - no evidence, no confirm. An earlier Claude reference run on the same
> case stays local-only / not shipped (case-neutral policy); the heavy-tier Qwen
> run independently reproduced that intrusion chain. The trust layer, the typed
> forensic tools, and the 16-step conductor are model-agnostic - only the
> provider/tier differs.
