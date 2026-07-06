# 🧑‍⚖️ Judge Quickstart

**Sentinel Ensemble** - Autonomous Digital Forensics & Incident Response /
Security Operations Center (DFIR/SOC) triage agent on Qwen Cloud (Alibaba
DashScope) · Track 4 Autopilot Agent · deterministic trust layer: **code, not
the LLM model, decides what is confirmed**
Author: Adil Eskintan · Repo: github.com/3sk1nt4n/Sentinel-Ensemble-Qwen
*(the engine's internal Python package keeps its historical name `sift_sentinel`;
the product is Sentinel Ensemble)*

Five minutes from clone to a verified end-to-end demo (**no evidence, no API
key** - `./setup.sh docker`, §2). A real investigation **on Qwen models hosted
on Alibaba Cloud** is then one line (first toolchain build ~15 min, once).

---

## 1️⃣ Prerequisites

**Judge path: Docker, any OS** (Windows/macOS/Linux) - no forensic-toolchain
install; the image bundles **every** tool the agent calls (full guide:
[`docs/DOCKER.md`](docs/DOCKER.md)). *Windows judges: open **PowerShell** and use
`.\setup.cmd` (no setup needed). macOS/Linux: open the **Terminal** and use `./setup.sh`.*

> **🆕 Brand-new computer?** Install **[Docker Desktop](https://www.docker.com/products/docker-desktop/)**
> once (Windows: keep WSL2; macOS: pick Apple-chip or Intel, then open it once),
> plus **Git**. That's the only setup - the image brings every forensic tool.
> On **Linux**, `./setup.sh docker` even installs Docker for you.

| Requirement | Version | Notes |
|---|---|---|
| **Docker** | current | the only prerequisite - and if it's missing, `./setup.sh docker` **offers to install it for you** (Linux: official script; Windows/macOS: it guides you to Docker Desktop). Demo image ~290 MB, full toolchain ~1 GB |
| Host resources | **≥ 8 GB RAM · ≥ 80 GB disk** | the run copies evidence to scratch and writes GBs of tool output; keep several × the evidence size free (hard floor 1 GB, override `SIFT_RUN_MIN_FREE_MB`) |
| Qwen Cloud API key | DashScope / Model Studio | request the **$40 hackathon voucher**; create an API key in Model Studio (see §3). (`--demo` needs none.) |
| Evidence | - | memory (`.img`/`.raw`/`.vmem`/`.mem`) and/or disk (`.E01`) in one folder (exported `.evtx` event logs ride along) - **free verified public cases in §4** |

---

## 2️⃣ Install

> **Which terminal?** 🪟 **Windows** → open **PowerShell** and use `.\setup.cmd`
> (needs no setup; `./setup.sh` is the Mac/Linux one and does nothing on Windows).
> 🍎🐧 **macOS/Linux** → open the **Terminal** and use `./setup.sh`. Run each line
> separately (older PowerShell rejects `&&`).

**🪟 Windows - PowerShell:**
```powershell
git clone https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen.git
cd Sentinel-Ensemble-Qwen
.\setup.cmd docker          # builds the demo image (~30 s) + runs it - no key, no evidence
```

**🍎🐧 macOS / Linux - Terminal:**
```bash
git clone https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen.git
cd Sentinel-Ensemble-Qwen
./setup.sh docker           # builds the demo image (~30 s) + runs it - no key, no evidence
```

You'll know it worked when the demo prints a synthetic case card ending in
**"Everything verified and ready."** 🎉

---

## 3️⃣ Add your Qwen Cloud API key

The live run calls **Qwen models on Alibaba Cloud (DashScope / Model Studio)**.
Provider + model are env-driven, so no code change is needed.

1. Request the **$40 Qwen Cloud voucher**, then in **Model Studio** (Singapore /
   International region) → **API Keys** → **Create API Key** → copy the `sk-…`
   (direct portal: **home.qwencloud.com/api-keys**).
2. Point Sentinel Ensemble at it:

```bash
cp .env.qwen.example .env      # then set DASHSCOPE_API_KEY in .env
# `./setup.sh` forwards it (and every SIFT_* setting) into the container.
# Or skip this entirely: `./setup.sh` asks for the key once, hidden.
```

3. Connectivity check (one call, reuses the demo image from §2):

```bash
docker run --rm -e SIFT_LLM_PROVIDER=qwen -e DASHSCOPE_API_KEY=sk-... \
  --entrypoint python3 sentinel-qwen:demo scripts/qwen_smoke.py
```

The international (Singapore) DashScope endpoint is the default; set
`DASHSCOPE_BASE_URL` for the mainland-China endpoint. The key is read at call
time and **never echoed, logged, or written to disk** by the pipeline.

> **Anthropic fallback (optional).** The provider seam keeps `anthropic` as the
> zero-regression fallback - unset `SIFT_LLM_PROVIDER` and set `ANTHROPIC_API_KEY`
> to run the identical pipeline on Claude. Not needed for this submission.

---

## 4️⃣ Run a real investigation

> **Need a case?** Any Windows memory (`.img`/`.raw`/`.vmem`/`.mem`) and/or disk
> (`.E01`) evidence in one folder works (exported `.evtx` event logs in the same
> folder are picked up too). Free, direct-download public cases (no login; links
> verified 2026-07-05):
>
> | Case | Shape | Size |
> |---|---|---|
> | **DFIR Madness "The Stolen Szechuan Sauce"** - [DC01 memory](https://dfirmadness.com/case001/DC01-memory.zip) + [DC01 disk](https://dfirmadness.com/case001/DC01-E01.zip), unzip both into one folder | **paired memory + disk** (Server 2012 R2) - recommended | 0.6 + 4.8 GB |
> | **NIST CFReDS "Data Leakage Case"** - [PC disk image](https://cfreds-archive.nist.gov/data_leakage_case/images/pc/cfreds_2015_data_leakage_pc.E01) | disk-only (Windows 7) - smallest | 2.1 GB |
> | **Digital Corpora "Lone Wolf"** - [image files](https://downloads.digitalcorpora.org/corpora/scenarios/2018-lonewolf/) | paired (Windows 10) - large | ~32 GB |

**One line** - builds the toolchain image on first use (~15 min, once), wires
every flag (FUSE caps for `.E01`, `SIFT_HTTP_TIMEOUT`, `SIFT_ALLOW_YARA`),
forwards the key from `.env`/env (or asks once, hidden), mounts the case
**read-only**, and saves the report to `sentinel-results/<case>/` on your machine:

**🪟 Windows - PowerShell:**
```powershell
.\setup.cmd C:\path\to\case-folder      # just the folder - no "run" keyword needed
```

**🍎🐧 macOS / Linux - Terminal:**
```bash
./setup.sh /path/to/case-folder         # just the folder - no "run" keyword needed
```

> 💡 Or run just `.\setup.cmd` (Windows) / `./setup.sh` (Mac/Linux) and **drag your
> evidence folder** into the window when it asks - no path to type.

<details>
<summary>What that one line runs (manual docker command)</summary>

```bash
docker build -t sentinel-qwen .          # full-plus toolchain image, ~15 min once
docker run --rm -it \
  --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined \
  -e SIFT_LLM_PROVIDER=qwen -e DASHSCOPE_API_KEY=sk-... \
  -e SIFT_DEFAULT_MODEL=qwen3.7-max \
  -e SIFT_HTTP_TIMEOUT=600 -e SIFT_ALLOW_YARA=1 \
  -v /path/to/case-folder:/evidence:ro \
  sentinel-qwen /evidence
```

</details>

What happens next (a couple of prompts, then it runs):

1. It scans the evidence and shows a **case card** - memory/disk, OS, health,
   sizes, read-only mount status. Just read it.
2. It asks the **analysis depth** - `1` (or Enter) = ⚡ HEAVY (flagship;
   `qwen3.7-max` on the Qwen config), `2` = 🪶 LIGHT (`qwen-plus`, cheaper). The
   model per tier is env-driven (see [`.env.qwen.example`](.env.qwen.example)).
   **Choosing the depth launches the run.**
3. The **`🔑 API key`** step - if you configured it in §3 (`.env` or
   `DASHSCOPE_API_KEY`), the launcher forwards it automatically; otherwise
   it asks once at a **hidden prompt** (never echoed, logged, or stored).
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
prefer `.\setup.cmd` / `./setup.sh` (which invoke `findevil.sh`, the container
entrypoint, for you) unless you are developing.
</details>

---

## 5️⃣ What you get

The launcher saves the results **on your machine** in
`sentinel-results/<case-name>/` (inside the repo folder) - the container is
ephemeral, but these files persist:

| Artifact | What it is |
|---|---|
| `report.md` | the investigative narrative - findings first, plain-English "why it matters", WHO/WHEN context, network-IOC roll-up |
| `run_summary.md` | tools · dispositions · cost · tokens · **LLM provider / model** (proves the run executed on Qwen; full `llm_provider`/`llm_endpoint` provenance is also in the run summary JSON, §7) |
| `agent_execution_log.txt` | append-only execution log - every tool call, timestamps, token usage, the 4-model ensemble, validator verdicts, Step-13AA reasoning |
| `summary_report_<timestamp>.html` | interactive one-page summary |
| `incident_report_YYYYMMDD.md` | dated copy of the final report |
| `finding_disposition_buckets.json` | confirmed / needs-review / benign / FP buckets with reasons |

> Per the **case-neutral repo policy**, run outputs (which contain case-specific
> IOCs) are **not committed** to the public repo - reproduce them by running
> `./setup.sh /path/to/case` on your evidence; the demo video shows a live
> Qwen run end to end.

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

A **July 1 reproduction** re-confirmed the chain (3 confirmed / 0 inconclusive
- normal model non-determinism), and a **flags-off ablation** on the same case
measured the trust layer directly (1 confirmed / 11 inconclusive without it).
All **four** run JSONs are shipped in [`docs/qwen-runs/`](docs/qwen-runs/).

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

Focused, green proofs of the core guarantees (each runs in seconds). No local
Python needed - the demo image from §2 carries the tests and the audit:

```bash
docker run --rm --entrypoint python3 sentinel-qwen:demo -m pytest -q tests/test_llm_provider.py   # Qwen/DashScope seam - 17 pass, 1 skip (the skip needs the optional anthropic fallback pkg)
docker run --rm --entrypoint python3 sentinel-qwen:demo audit/nocheat.py   # dataset-agnostic gate -> NO_CHEAT_AUDIT_PASS
```

<details>
<summary>Native equivalents (dev checkout with Python 3.10+)</summary>

```bash
PYTHONPATH=src python3 -m pytest -q tests/test_llm_provider.py           # Qwen/DashScope seam (18)
PYTHONPATH=src python3 -m pytest -q tests/test_agnostic_contract.py \
    tests/test_onboard_agnostic.py tests/test_secret_input_guard.py      # dataset-agnostic + no-secret guards
python3 audit/nocheat.py                                                 # dataset-agnostic gate -> NO_CHEAT_AUDIT_PASS
```

</details>

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
| `.\setup.cmd` / `./setup.sh` "not recognized" or nothing happens | wrong terminal: **Windows** → **`.\setup.cmd`** in **PowerShell**; **macOS/Linux** → `./setup.sh` in the **Terminal**. Run each line separately (older PowerShell rejects `&&`). `.\setup.cmd` needs no policy change; only if you chose `.\setup.ps1` directly: `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` |
| No Docker / daemon not running | install/start **Docker Desktop** (docker.com); on **Linux** `./setup.sh docker` even offers to install Docker for you and falls back to `sudo docker` automatically |
| `.E01` disk won't mount | launch via `.\setup.cmd C:\path\to\case` / `./setup.sh /path/to/case` - it passes the required FUSE capabilities automatically (manual flags: [`docs/DOCKER.md`](docs/DOCKER.md) §3) |
| "Vol3 ISF profile not found" | Volatility 3 can't identify the memory image OS - the pipeline falls back to profile-independent scanning. Expected on some evidence sets. |
| "SSDT trust: degraded" | the kernel-integrity check found hooked/unresolvable entries - memory-based confidence is capped at MEDIUM. A feature, not a bug. |
| "DashScope HTTP 429" | DashScope rate limit on the parallel 4-model ensemble - the client retries with backoff (429/5xx); if it persists, pace the run or check your Model Studio quota. |
| "model not found" / 400 | confirm the exact model IDs in your Model Studio list (`qwen3.7-max`, `qwen-plus`); `max_tokens` is auto-clamped to the model's output cap. |
| The run doesn't start after you pick depth | you ran `step0_onboard.py` directly (staged / dev mode) - use `.\setup.cmd` / `./setup.sh` / `findevil.sh`, which are live by default. |

---

*Sentinel Ensemble - Adil Eskintan - Global AI Hackathon with Qwen Cloud, Track 4 (Autopilot Agent)*
