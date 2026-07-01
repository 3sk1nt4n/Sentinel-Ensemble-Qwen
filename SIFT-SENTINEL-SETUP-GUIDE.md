# 🛠️ Sentinel Ensemble - Complete Setup Guide

From a blank computer to your first finished investigation - every step
numbered, nothing assumed. If you only want the short version, the
[README](README.md) quick start covers it; this guide is the long form with
explanations, for anyone setting up from zero.

*(Internal Python package name: `sift_sentinel`.)*

---

## Phase A - The platform (the free SANS SIFT VM)

Sentinel Ensemble runs on the SANS SIFT Workstation because SIFT ships the
court-vetted forensic tooling pre-installed: Volatility 3, Sleuth Kit, EWF
tools, Plaso. You install almost nothing.

### A.1 Get the SIFT Workstation

1. Go to the official SANS SIFT page:
   **https://sans.org/tools/sift-workstation**.
2. Download the **pre-built VM appliance (`.ova`)** (easiest) - or run the
   installer on a clean Ubuntu 22.04 system.

### A.2 Import the VM

1. Install **VMware Workstation Player** or **VirtualBox** (both free).
2. *File → Open/Import Appliance → select the downloaded file → Import*.
3. Give the VM **≥ 8 GB RAM** and **≥ 80 GB disk**. More RAM = faster
   memory-image analysis.

### A.3 First boot

1. Start the VM. Default SIFT credentials: user **`sansforensics`**,
   password **`forensics`**.
2. Open a terminal - everything below happens there.
3. Sanity check the forensic tooling (all pre-installed):

```bash
python3 -c "import volatility3; print('Volatility 3: OK')"
fls -V                  # Sleuth Kit
ewfinfo -h | head -2    # EWF tools
```

---

## Phase B - The AI brain (Qwen Cloud API key)

This edition runs on **Qwen models hosted on Alibaba Cloud (DashScope / Model
Studio)** by default.

1. Sign up at **https://qwencloud.com** (Alibaba Cloud Model Studio) - hackathon
   participants can request the **$40 Qwen Cloud voucher**.
2. **Model Studio (Singapore / International region) → API Keys → Create API
   Key** → copy the `sk-…` string.
3. Give it to Sentinel Ensemble in **any one of three ways** - you can't get
   stuck (a real key always wins; a bad one falls through to the next):

| | Option | How | Notes |
|---|---|---|---|
| **①** | **🚀 Just run it & paste** *(recommended)* | At the `🔑 API key` step the launcher asks you at a **hidden prompt** - paste, press Enter. | Verified live · session only · **never echoed, logged, or saved to disk**. |
| **②** | **📄 A visible file** *(set once)* | Open **`API_KEY.txt`** in the repo root, replace the placeholder on the **last line**, **save**. | Auto-created on first run · **gitignored** (never committed) · no prompt next time. |
| **③** | **🌐 Environment file** | `cp .env.qwen.example .env`, set `DASHSCOPE_API_KEY=sk-…` (provider + model tiering are preset), then `python3 scripts/qwen_smoke.py` to verify connectivity. | For CI / power users. |

> **Anthropic fallback (optional):** unset `SIFT_LLM_PROVIDER` and set
> `ANTHROPIC_API_KEY=sk-ant-…` to run the identical pipeline on Claude via the
> same provider seam. Not needed for the Qwen Cloud submission.

> **🔓 Order & self-healing:** the launcher checks **env var → `.env` →
> `API_KEY.txt`**. A real key always beats a placeholder, and if the environment
> key is rejected (e.g. a stale `export` in `~/.bashrc`) it **falls back** to a
> valid key in your file *before* asking - so the file you edited always works.

💰 **Cost expectations:** the `--demo` mode is free (no key needed). A real
investigation in fast/economical mode typically costs a dollar or two; the
deepest-reasoning mode costs more - the launcher shows the price range next
to each option, and the finished report shows the **real** bill.

---

## Phase C - Install Sentinel Ensemble

```bash
git clone https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen.git
cd Sentinel-Ensemble-Qwen
pip install -r requirements.txt
```

> **PEP 668 note (newer Ubuntu):** if `pip install` is refused with
> "externally managed environment", either use a virtual environment -
> `python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt`
> - or add `--break-system-packages`. The SIFT 22.04 VM accepts the plain command.

### Prove the install works (free, no evidence, no key)

```bash
./findevil.sh --demo
```

You should see a synthetic case card ending in
**"Everything verified and ready."** - that one line means Python deps,
forensic tooling, and the launcher are all healthy. 🎉

---

## Phase D - Get evidence to investigate

Any of these work - the pipeline auto-detects what you give it
(memory-only, disk-only, or both together):

| Source | What you get |
|---|---|
| **Official hackathon starter case data** - **[download](https://sansorg.egnyte.com/fl/HhH7crTYT4JK)** (also on the Protocol SIFT Slack, per the official rules) | ready-made disk + memory case data |
| Your own captures | `.E01`/`.raw` disk images · `.raw`/`.vmem`/`.img` memory · exported `.evtx` logs |

Put everything for **one case in one folder**, for example:

```
/cases/evidence/my-case/
├── workstation-memory.img      ← memory image
└── workstation-cdrive.E01      ← disk image (same machine = strongest pair)
```

🔒 You never need to mount or convert anything yourself - onboarding probes
file *content* (not file names), mounts disks **read-only**, and
SHA256-fingerprints everything before and after the run (chain of custody
by math, not promises).

---

## Phase E - Run your first investigation

```bash
./findevil.sh /cases/evidence/my-case
```

The conversation, start to finish:

1. **Case card** - it scans the evidence and shows what it found: memory vs
   disk, the Windows version (cross-checked between disk and memory), health
   probes, read-only mount status. Just read it.
2. **Analysis depth** - type `2` for fast & economical, or `1` for deepest
   reasoning. (Enter defaults to the deep option - pick `2` for a first run.)
3. **API key** - paste at the hidden prompt if asked (screen stays blank
   while pasting; that's normal).
4. Type **`FIND`** and watch. A full paired-image case finishes in minutes,
   not hours. Touch nothing.

### Useful variations

```bash
./findevil.sh                      # no path? it asks ONE question
./findevil.sh --demo               # synthetic walkthrough, free
./findevil.sh --dry-run /cases/evidence/my-case
                                   # full onboarding + printed plan,
                                   # pipeline NOT executed (also free)
```

---

## Phase F - Read the results

| Artifact | What it is |
|---|---|
| `report.md` | the investigative narrative - findings first, plain-English "why it matters" per finding, WHO/WHEN context, network-IOC roll-up |
| customer findings table | one row per finding: who, when, disposition, tools that proved it |
| `finding_disposition_buckets.json` | confirmed / needs-review / benign / inconclusive, each with reasoning - written to the run directory; `report.md` renders from it |
| `agent_execution_log.txt` | append-only log of every tool call (timestamps, token usage) |
| `reports/incident_report_YYYYMMDD.md` | dated copy of the final report |

The habit worth forming: pick any finding, note its id, and trace it -
report → disposition bucket → `source_tools` → audit log. Every claim
survives that walk; that's the whole point of the architecture.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `pip install` refused (PEP 668) | venv or `--break-system-packages` (Phase C note) |
| `ERROR: Missing dependencies` from findevil.sh | run the Phase C install line, retry |
| Demo doesn't end with "Everything verified and ready." | read the line it printed instead - the launcher names the missing piece |
| Typing `FIND` doesn't launch | you ran `step0_onboard.py` directly (staged by default for developers) - use `./findevil.sh` |
| "Vol3 ISF profile not found" during a run | expected on some images - the pipeline falls back to profile-independent scanning |
| API key rejected (401) | the key is invalid/expired, or its region doesn't match the endpoint (intl key ↔ intl endpoint) - create a fresh one in Model Studio; the launcher re-prompts |

---

## Where to go next

- [`README.md`](README.md) - product overview + compliance checklist
- [`JUDGE-QUICKSTART.md`](JUDGE-QUICKSTART.md) - the 5-minute judge path
- [`ARCHITECTURE.md`](ARCHITECTURE.md) - the 16-step pipeline + 14 defense layers
- [`ONBOARDING.md`](ONBOARDING.md) - contributing to the codebase
- [`docs/`](docs/) - dataset, accuracy report, schema, pipeline internals

*Sentinel Ensemble - Adil Eskintan - Global AI Hackathon with Qwen Cloud, Track 4 (Autopilot Agent)*
