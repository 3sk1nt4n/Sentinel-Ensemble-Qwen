# 🧑‍⚖️ Judge Quickstart

**Sentinel Ensemble** - Agentic DFIR Pipeline · Find Evil! AI Hackathon 2026
Author: Adil Eskintan · Repo: github.com/3sk1nt4n/Sentinel-Ensemble
*(internal Python package name: `sift_sentinel`)*

Five minutes from clone to a running investigation. The free `--demo` mode
needs **no evidence and no API key** - you can verify the whole flow first.

---

## 1️⃣ Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| SANS SIFT Workstation | Ubuntu 22.04+ | free VM from SANS - **[download](https://sans.org/tools/sift-workstation)**; ships Volatility 3, Sleuth Kit, EWF tools, Plaso |
| VM resources | **≥ 8 GB RAM · ≥ 80 GB disk** | 8 GB is the SIFT default; give more RAM for large memory images. The run copies the evidence to `/tmp` and writes GBs of tool output, so keep several × the evidence size free (hard floor: 1 GB, override `SIFT_RUN_MIN_FREE_MB`). |
| Python | 3.10+ | ships with SIFT |
| Anthropic API key | **Tier 2+** | Three easy ways - see **§3 below**: paste at the hidden prompt, a visible **`API_KEY.txt`**, or `export ANTHROPIC_API_KEY=...`. (`--demo` needs none.) |
| Evidence | - | memory (`.img`/`.raw`/`.vmem`) and/or disk (`.E01`) in one folder |

> ⚠️ **API tier:** the analysis stage runs a **4-model ensemble in parallel**
> (4 concurrent API calls), so a **Tier-1** key ($5) is likely to hit rate
> limits (HTTP 429). Use **at least Tier-2** ($40) - **Tier-3** ($200) is
> smoothest. `--demo` needs no key and no tier. Check / raise your tier at
> **https://platform.claude.com/settings/limits**.

No additional forensic tool installation is required on SIFT. (One Python
package, `pycryptodome`, is in `requirements.txt` - see
[`ENVIRONMENT.md`](ENVIRONMENT.md) for why it matters.)

---

## 2️⃣ Install

```bash
git clone https://github.com/3sk1nt4n/Sentinel-Ensemble.git
cd Sentinel-Ensemble
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

## 3️⃣ Add your Anthropic API key

The live run needs an Anthropic API key (the `--demo` above does **not**). Pick
whichever way is easiest - and a **real** key always wins over a leftover
placeholder, so you can't get stuck:

**A. Just run it and paste** - *simplest; nothing to find or edit.*
When the launcher reaches the `🔑 API key` step it asks for your key at a **hidden
prompt**. Paste it (the screen stays blank while pasting - that's normal) and press
Enter. It's verified live, used for this session only, and **never echoed, logged,
or written to disk**.

**B. A visible file** - *set it once, no prompt next time.*
Open **`API_KEY.txt`** in the repo root (the launcher creates it for you on first
run), replace the `sk-ant-xxxx…` placeholder on the **last line** with your key,
and **save**. It's picked up automatically on the next run. The file is
**gitignored**, so your key is never committed.

**C. An environment variable** - `export ANTHROPIC_API_KEY=sk-ant-...`
(a hidden `.env` file containing `ANTHROPIC_API_KEY=…` works too).

> **Order & self-healing.** The launcher checks **env var → `.env` → `API_KEY.txt`**.
> If the environment key is rejected - e.g. a stale `export` still in your shell -
> it automatically falls back to a valid key in `API_KEY.txt` / `.env` *before*
> asking you to paste, so the file you just edited always works.

Get a key at **https://console.anthropic.com → API keys → Create key**. Use a
**Tier-2+** key for the parallel ensemble (see the tier note in Prerequisites
above).

---

## 4️⃣ Run a real investigation

> **Need a case?** Use the **official hackathon starter case data** -
> **[download](https://sansorg.egnyte.com/fl/HhH7crTYT4JK)** (also posted on the
> Protocol SIFT Slack, per the rules): a ready-made memory + disk pair. Or point it
> at your own `.E01`/`.raw` disk and `.img`/`.raw`/`.vmem` memory in one folder.

```bash
./findevil.sh /path/to/case-folder
```

What happens next (a couple of prompts, then it runs):

1. It scans the evidence and shows a **case card** - what it found
   (memory/disk, OS, health), sizes, read-only mount status. Just read it.
2. It asks the **analysis depth** - `1` (or Enter) = ⚡ HEAVY (Claude Opus 4.8,
   ~$8-15/case), `2` = 🪶 LIGHT (Claude Haiku 4.5, ~$2-3/case). **Choosing the
   depth launches the run** - there's nothing else to type.
3. The **`🔑 API key`** step - if you already set your key (file or env, §3),
   it's used automatically and skipped; otherwise paste it at the **hidden
   prompt** (blank screen while pasting is normal; never echoed or saved to disk).
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
| `report.md` | the investigative narrative - findings first, plain-English "why it matters", WHO/WHEN context, network-IOC roll-up (the per-finding customer table renders into its sections) |
| `run_summary.md` | tools · dispositions · cost · tokens at a glance |
| `agent_execution_log.txt` | append-only execution log - every tool call, timestamps, token usage, the 4-model ensemble, validator verdicts, and Step-13AA reasoning |
| `summary_report.html` | interactive one-page summary |
| `reports/incident_report_YYYYMMDD.md` | dated copy of the final report |

> The files above ship in [`artifacts/run-rd01/`](artifacts/run-rd01/) for inspection. A **live run** additionally writes `finding_disposition_buckets.json` - the confirmed / needs-review / benign / inconclusive buckets that `report.md` §1/§3/§4 are rendered from - to its run directory.

Every finding links to the exact tool execution that proved it - pick any
claim and trace it to raw tool output in seconds.

---

## 6️⃣ Numbers from a real proven run

Paired Windows case (memory + disk, ~15 GB), 4-member **Claude Opus 4.8**
ensemble - the same run shipped in [`artifacts/run-rd01/`](artifacts/run-rd01/)
and detailed in [`ARCHITECTURE.md`](ARCHITECTURE.md) and
[`docs/DATASET.md`](docs/DATASET.md):

| Metric | Value |
|---|---|
| Total elapsed | 509 s (~8.5 minutes) |
| Tools selected / data-producing / not-applicable / failed | 34 / 30 / 4 / **0** |
| Typed facts in EvidenceDB | 201,260 |
| Validator | 81 raw → 51 candidates · 22 blocked & routed to a final cross-check (never silently dropped) |
| Self-correction (Step 13AA) | 46 ambiguous findings re-judged · ~40 self-corrected (ReAct + 13AA) |
| Final disposition | 2 confirmed · 42 suspicious / needs-review · 5 benign · 49 total |
| Estimated cost | ~$15.45 with prompt caching |
| Evidence integrity | SHA256 MATCH (pre == post) |

*Full per-finding 13AA reasoning is in
[`artifacts/run-rd01/report.md`](artifacts/run-rd01/report.md) §4 and the raw
[`agent_execution_log.txt`](artifacts/run-rd01/agent_execution_log.txt).*

---

## 7️⃣ Verify the claims yourself

```bash
pytest tests/ -q             # 4,800+ tests collected
```

After a run, the judge-facing invariants - all checkable in the shipped
[`artifacts/run-rd01/`](artifacts/run-rd01/):

- **Integrity** - `report.md` §1 states the SHA256 pre/post comparison
  (`SHA256 MATCH - evidence unmodified`); the live verification is in
  `agent_execution_log.txt` (`INTEGRITY VERIFIED: all hashes match`).
- **Traceability** - pick any finding id in `report.md`, grep the same id in
  `agent_execution_log.txt`, and read its `source_tools` / per-finding
  evidence and the exact tool calls that produced it.
- **Self-correction** - `report.md` §4 summarizes Step-13AA; the raw decisions
  (`INV3A_FINALIZE moved=39/46`, the per-finding verdicts, and
  `INV3A_PROMOTION_DENIALS …`) are in `agent_execution_log.txt`, showing exactly
  where code overruled the model's `confirmed` verdict.
  👉 **[`SELF-CORRECTION-PROOF.md`](SELF-CORRECTION-PROOF.md)** lists *every*
  correction from this run - both layers, before → after, with the exact
  `agent_execution_log.txt` line for each.

---

## 🧯 Troubleshooting

| Symptom | What it means |
|---|---|
| "Vol3 ISF profile not found" | Volatility 3 can't identify the memory image OS - the pipeline falls back to profile-independent scanning. Expected on some evidence sets. |
| "SSDT trust: degraded" | the kernel-integrity check found hooked/unresolvable entries - memory-based confidence is capped at MEDIUM. A feature, not a bug. |
| "Rate limit 429" | your Anthropic tier is too low for the parallel 4-model ensemble - automatic retry/backoff is built in, but use **Tier-2+** (see Prerequisites; raise it at https://platform.claude.com/settings/limits). |
| `pip install` refused (PEP 668) | use a venv or `--break-system-packages` (see Install above). |
| The run doesn't start after you pick depth | you ran `step0_onboard.py` directly (staged / dev mode) - use `./findevil.sh`, which is live by default. |

---

*Sentinel Ensemble - Adil Eskintan - Find Evil! AI Hackathon 2026*
