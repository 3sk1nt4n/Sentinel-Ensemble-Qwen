# 🧑‍⚖️ Judge Quickstart

**Sentinel Ensemble** - Agentic DFIR Pipeline · Global AI Hackathon with Qwen Cloud, Track 4 (Autopilot Agent)
Author: Adil Eskintan · Repo: github.com/3sk1nt4n/Sentinel-Ensemble-Qwen
*(internal Python package name: `sift_sentinel`)*

Five minutes from clone to a running investigation **on Qwen models hosted on
Alibaba Cloud**. The free `--demo` mode needs **no evidence and no API key** - you
can verify the whole flow first.

---

## 1️⃣ Prerequisites

> **No SIFT VM? Fastest judge path:** Docker Desktop on any OS -
> `docker build --target demo -t sentinel-qwen:demo . && docker run --rm sentinel-qwen:demo`
> (~290 MB, no key, no evidence). Or `./setup.sh docker`. See README > Run it in Docker.

| Requirement | Version | Notes |
|---|---|---|
| SANS SIFT Workstation | Ubuntu 22.04+ | free VM from SANS - **[download](https://sans.org/tools/sift-workstation)**; ships Volatility 3, Sleuth Kit, EWF tools, Plaso |
| VM resources | **≥ 8 GB RAM · ≥ 80 GB disk** | the run copies evidence to `/tmp` and writes GBs of tool output; keep several × the evidence size free (hard floor 1 GB, override `SIFT_RUN_MIN_FREE_MB`) |
| Python | 3.10+ | ships with SIFT |
| Qwen Cloud API key | DashScope / Model Studio | request the **$40 hackathon voucher**; create an API key in Model Studio (see §3). (`--demo` needs none.) |
| Evidence | - | memory (`.img`/`.raw`/`.vmem`) and/or disk (`.E01`) in one folder |

No additional forensic tool installation is required on SIFT. (One Python
package, `pycryptodome`, is in `requirements.txt` - see
[`ENVIRONMENT.md`](ENVIRONMENT.md) for why it matters.)

---

## 2️⃣ Install

```bash
git clone https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen.git
cd Sentinel-Ensemble-Qwen
pip install -r requirements.txt
./findevil.sh --demo        # smoke test - no evidence, no API key
```

You'll know it worked when the demo prints a synthetic case card ending in
**"Everything verified and ready."** 🎉

> On newer Ubuntu (PEP 668 "externally managed environment") plain
> `pip install` is refused - use a venv
> (`python3 -m venv .venv && . .venv/bin/activate`) or add
> `--break-system-packages`. The SIFT 22.04 VM accepts the plain command.

---

## 3️⃣ Add your Qwen Cloud API key

The live run calls **Qwen models on Alibaba Cloud (DashScope / Model Studio)**.
Provider + model are env-driven, so no code change is needed.

1. Request the **$40 Qwen Cloud voucher**, then in **Model Studio** (Singapore /
   International region) → **API Keys** → **Create API Key** → copy the `sk-…`
   (direct portal: **home.qwencloud.com/api-keys**).
2. Point Sentinel Ensemble at it:

```bash
cp .env.qwen.example .env              # then set DASHSCOPE_API_KEY in .env
# or export directly:
export SIFT_LLM_PROVIDER=qwen
export DASHSCOPE_API_KEY=sk-...        # QWEN_API_KEY also accepted
export SIFT_DEFAULT_MODEL=qwen3.7-max
python3 scripts/qwen_smoke.py          # one-call connectivity check before a full run
```

The international (Singapore) DashScope endpoint is the default; set
`DASHSCOPE_BASE_URL` for the mainland-China endpoint. The key is read at call
time and **never echoed, logged, or written to disk** by the pipeline.

> **Anthropic fallback (optional).** The provider seam keeps `anthropic` as the
> zero-regression fallback - unset `SIFT_LLM_PROVIDER` and set `ANTHROPIC_API_KEY`
> to run the identical pipeline on Claude. Not needed for this submission.

---

## 4️⃣ Run a real investigation

> **Need a case?** Point it at any Windows memory (`.img`/`.raw`/`.vmem`) and/or
> disk (`.E01`) evidence in one folder - e.g. a public SANS IR image.

```bash
./findevil.sh /path/to/case-folder
```

What happens next (a couple of prompts, then it runs):

1. It scans the evidence and shows a **case card** - memory/disk, OS, health,
   sizes, read-only mount status. Just read it.
2. It asks the **analysis depth** - `1` (or Enter) = ⚡ HEAVY (flagship;
   `qwen3.7-max` on the Qwen config), `2` = 🪶 LIGHT (`qwen-plus`, cheaper). The
   model per tier is env-driven (see [`.env.qwen.example`](.env.qwen.example)).
   **Choosing the depth launches the run.**
3. The **`🔑 API key`** step - if you set `DASHSCOPE_API_KEY` (file or env, §3)
   it's used automatically; otherwise paste it at the **hidden prompt**.
4. Then touch nothing - minutes, not hours.

<details>
<summary>Direct pipeline invocation (what the launcher runs for you)</summary>

```bash
python3 run_pipeline.py --live --inv2-ensemble \
  --image  /path/to/memory.img \
  --disk   /path/to/cdrive.E01 \
  --disk-mount /path/to/mounted_windows_partition
```

The launcher handles read-only mounting and flag wiring automatically -
prefer `./findevil.sh` unless you are developing.
</details>

---

## 5️⃣ What you get

| Artifact | What it is |
|---|---|
| `report.md` | the investigative narrative - findings first, plain-English "why it matters", WHO/WHEN context, network-IOC roll-up |
| `run_summary.md` | tools · dispositions · cost · tokens · **`llm_provider` / `model`** (proves the run executed on Qwen) |
| `agent_execution_log.txt` | append-only execution log - every tool call, timestamps, token usage, the 4-model ensemble, validator verdicts, Step-13AA reasoning |
| `summary_report.html` | interactive one-page summary |
| `reports/incident_report_YYYYMMDD.md` | dated copy of the final report |

> A live run writes these (plus `finding_disposition_buckets.json`) into its run
> directory. Per the **case-neutral repo policy**, run outputs (which contain
> case-specific IOCs) are **not committed** to the public repo - reproduce them
> by running `./findevil.sh` on your evidence; the demo video shows a live Qwen
> run end to end.

Every finding links to the exact tool execution that proved it - pick any
claim and trace it to raw tool output in seconds.

---

## 6️⃣ Verified Qwen Cloud runs

Two full **paired (memory + disk)** investigations ran end-to-end on **Qwen models
on Alibaba Cloud DashScope**, through the full trust-layer pipeline - the same
deterministic layer, two model tiers. Numbers are straight from each run's summary
JSON; the full comparison + honesty notes are in
[`QWEN-SUBMISSION.md`](QWEN-SUBMISSION.md).

| | Light (`qwen-plus` ×4) | Heavy (`qwen3.7-max`) |
|---|---|---|
| Findings (final) | 11 | 34 |
| **Confirmed malicious** | **0** | **4** |
| Runtime | 5m 37s | 14m 44s |
| Cost (cache-aware, est.) | ~$0.28 | ~$1.53 |
| Integrity (mem + disk) | MATCH | MATCH |

The light tier confirmed **nothing** - no atomic proof, no confirm (the trust
layer working as designed, not a gap). The heavy tier reconstructed the intrusion
chain and **4 findings cleared every confirmation gate** (PsExec lateral movement,
PWDumpX credential dumping, an IFEO `sethc.exe` sticky-keys backdoor, `p.exe` from
a temp dir). **The trust layer is the constant; the model tier just changes how
much clears the bar.**

<details><summary>Earlier Claude reference run (architecture-proving, local / not committed)</summary>

Before the Qwen port, the same architecture was proven end-to-end on a Claude
reference run (kept local per the case-neutral policy, ~$15.45): 509 s, 34 tools
(30 data-producing / 0 failed), 201,260 typed facts, 2 confirmed / 42 suspicious /
5 benign / 49 total, SHA256 MATCH. It is **not** a Qwen result and is **not**
shipped; the Qwen runs above independently reproduced the intrusion chain. It is
kept only to show the trust layer, the 195 typed tools, and the 16-step conductor
are model-agnostic - only the provider/tier differs.
</details>

---

## 7️⃣ Verify the claims yourself

Focused, green proofs of the core guarantees (each runs in seconds):
```bash
PYTHONPATH=src python3 -m pytest -q tests/test_llm_provider.py           # Qwen/DashScope seam (18)
PYTHONPATH=src python3 -m pytest -q tests/test_agnostic_contract.py \
    tests/test_onboard_agnostic.py tests/test_secret_input_guard.py      # dataset-agnostic + no-secret guards
python3 audit/nocheat.py                                                 # dataset-agnostic gate -> NO_CHEAT_AUDIT_PASS
```

> The full suite is large and green by default: `pytest tests/ -q` -> **4,700+
> passed, 0 failed** (~2 min). A batch of legacy forensic-parser tests that went
> stale after tool-signature refactors is quarantined (skipped) with the honest
> state documented in [`tests/QUARANTINE.md`](tests/QUARANTINE.md); run them
> anyway with `SIFT_RUN_QUARANTINED=1`.

After a run, the judge-facing invariants:

- **Provider proof** - the run summary JSON records `llm_provider` / `model` /
  `llm_endpoint` (sanitized aggregates shipped in
  [`docs/qwen-runs/`](docs/qwen-runs/)), so the artifact shows the run executed
  on Qwen Cloud / DashScope.
- **Integrity** - `report.md` §1 states the SHA256 pre/post comparison; the live
  verification is in `agent_execution_log.txt` (`INTEGRITY VERIFIED`).
- **Traceability** - pick any finding id in `report.md`, grep the same id in
  `agent_execution_log.txt`, and read its `source_tools` and the exact tool calls
  that produced it.
- **Self-correction** - `report.md` §4 summarizes Step-13AA; the raw decisions
  (`INV3A_FINALIZE`, per-finding verdicts, `INV3A_PROMOTION_DENIALS`) are in
  `agent_execution_log.txt`, showing exactly where code overruled the model's
  `confirmed` verdict. See **[`SELF-CORRECTION-PROOF.md`](SELF-CORRECTION-PROOF.md)**.

---

## 🧯 Troubleshooting

| Symptom | What it means |
|---|---|
| "Vol3 ISF profile not found" | Volatility 3 can't identify the memory image OS - the pipeline falls back to profile-independent scanning. Expected on some evidence sets. |
| "SSDT trust: degraded" | the kernel-integrity check found hooked/unresolvable entries - memory-based confidence is capped at MEDIUM. A feature, not a bug. |
| "DashScope HTTP 429" | DashScope rate limit on the parallel 4-model ensemble - the client retries with backoff (429/5xx); if it persists, pace the run or check your Model Studio quota. |
| "model not found" / 400 | confirm the exact model IDs in your Model Studio list (`qwen3.7-max`, `qwen-plus`); `max_tokens` is auto-clamped to the model's output cap. |
| `pip install` refused (PEP 668) | use a venv or `--break-system-packages` (see Install above). |
| The run doesn't start after you pick depth | you ran `step0_onboard.py` directly (staged / dev mode) - use `./findevil.sh`, which is live by default. |

---

*Sentinel Ensemble - Adil Eskintan - Global AI Hackathon with Qwen Cloud, Track 4 (Autopilot Agent)*
