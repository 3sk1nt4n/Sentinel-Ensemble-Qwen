# Deploying on Alibaba Cloud (Qwen Cloud) - runbook

Global AI Hackathon with Qwen Cloud - Track 4 (Autopilot Agent).

This is the turnkey path to satisfy the **Proof of Alibaba Cloud Deployment**
requirement: the agent's backend runs on **Alibaba Cloud ECS**, reasons via
**Qwen models on the Alibaba Cloud DashScope API**, and (optionally) stores
evidence/artifacts in **Alibaba Cloud OSS**.

```
                 Alibaba Cloud
  ┌────────────────────────────────────────────────┐
  │  ECS instance (Ubuntu)                         │
  │   - run_pipeline.py (the 16-step conductor)    │
  │   - forensic toolchain (Volatility 3, Sleuth   │
  │     Kit, EWF, Plaso) + the typed MCP server    │
  │            │                                   │
  │            ├──HTTPS──> DashScope API (Qwen)  ◄─┼── reasoning (llm_provider.py)
  │            │                                   │
  │            └──(opt)──> OSS bucket            ◄─┼── evidence in / report out
  └────────────────────────────────────────────────┘
```

The single code file that proves Alibaba Cloud API use is
[`src/sift_sentinel/llm_provider.py`](src/sift_sentinel/llm_provider.py) - it
issues live HTTPS calls to the DashScope endpoint.

---

## 0) Prerequisites (your Alibaba Cloud account)

- An **Alibaba Cloud** account (Qwen Cloud).
- A **DashScope / Qwen Cloud API key** - request the **$40 hackathon voucher**.
- An **SAS or ECS instance** (provisioned below - SAS is the 5-minute path).
- (Optional) an **OSS bucket** for evidence/artifact storage.

## 1) Provision the compute - SAS (5-minute path) or ECS

### Option A - Simple Application Server (SAS): the fast, fixed-price path

The official hackathon guide recommends SAS for LLM-API agents ("deploy in
under 5 minutes", predictable monthly billing). Ideal for the demo +
proof-of-deployment run; pick ECS (Option B) for full-evidence investigations.

1. **SAS Console** → **Create Server** → Region (Singapore matches the
   DashScope intl endpoint) → Image: an **OS image (Ubuntu 22.04)** or the
   **Docker application image** → cheapest plan → pay. The instance provisions
   immediately with a public IP.
2. **No default password:** on the instance card use **Reset Password** first.
3. **Connect** via the console's **Workbench** button (browser terminal, logs in
   as root - this is the same Workbench view the proof screenshot comes from).
4. Firewall (inbound-only, Firewall tab): the defaults (TCP 22/80/443 + ICMP)
   are enough - the agent only needs **outbound** HTTPS to DashScope.

### Option B - ECS (full control, for real evidence runs)

- Image: **Ubuntu 22.04 LTS** (or 24.04).
- Size: the agent copies evidence to local scratch and writes GBs of tool
  output, and memory images are large. Use **>= 8 vCPU / >= 16 GB RAM** and
  **>= 100 GB disk** as a floor; size RAM above the largest memory image you
  will analyse. (Override the storage floor with `SIFT_RUN_MIN_FREE_MB`.)
  For a demo/proof-only deployment the smallest instance works.
- Region: pick one near you; it sets the DashScope endpoint (see step 4).
- Login: prefer a **Key Pair** over passwords; connect via SSH or the console
  **Workbench**.
- Open outbound HTTPS (443) so the instance can reach the DashScope API; keep
  SSH (22) restricted to your own IP.

## 2) Install Docker + the agent on the instance (SAS or ECS)

```bash
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen.git
cd Sentinel-Ensemble-Qwen
./setup.sh docker   # installs Docker itself if missing (official script), then
                    # builds + runs the zero-cost demo - proves the flow end to end
```

The `sentinel-qwen` image bundles the **entire forensic toolchain**
([`docs/DOCKER.md`](docs/DOCKER.md)) - nothing else to install on the host.

## 3) Point it at Qwen (DashScope)

```bash
cp .env.qwen.example .env
# edit .env: set DASHSCOPE_API_KEY=...  (provider + model tiering are preset)
```
Key env (see `.env.qwen.example` for the full recommended set):
```bash
export SIFT_LLM_PROVIDER=qwen
export DASHSCOPE_API_KEY=sk-...
export SIFT_DEFAULT_MODEL=qwen3.7-max        # flagship; qwen-plus on high-volume stages
# Mainland-China region? override the endpoint:
# export DASHSCOPE_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions
```
Smoke-test the Alibaba Cloud connection before a full run (the single, canonical
smoke test - it hits the same DashScope seam the 16-step pipeline uses, using
the demo image already built in step 2):
```bash
sudo docker run --rm -e SIFT_LLM_PROVIDER=qwen -e DASHSCOPE_API_KEY=sk-... \
  --entrypoint python3 sentinel-qwen:demo scripts/qwen_smoke.py
```

## 4) (Optional) Evidence via Alibaba Cloud OSS

Keep evidence in an OSS bucket and pull it to the ECS scratch disk before a run
(read-only is preserved once mounted):
```bash
ossutil cp oss://<bucket>/<case>/  /cases/evidence/<case>/ --recursive
```
Report artifacts can be pushed back to OSS after the run.

## 5) Run an investigation (on Qwen, on Alibaba Cloud)

```bash
sudo ./setup.sh /cases/evidence/<case>   # ONE line - image, key (.env), flags, read-only mount
```
Evidence is mounted **read-only** and SHA256-fingerprinted pre/post (chain of
custody); the report lands in the run directory (and optionally OSS). The
manual `docker run` equivalent is in [`JUDGE-QUICKSTART.md`](JUDGE-QUICKSTART.md) §4.

## 6) Capture the Proof of Deployment (REQUIRED - "no proof = not eligible")

Per the Devpost x Qwen Cloud rules, Proof of Deployment on Alibaba Cloud has
**two mandatory parts**:

**Part 1 - code file with the Qwen Cloud Base URL (already satisfied).** Link
[`src/sift_sentinel/llm_provider.py`](src/sift_sentinel/llm_provider.py) in the
submission - it hardcodes the DashScope base URL judges look for:
`https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions`.

**Part 2 - a screenshot of running resources from your Alibaba Cloud Workbench.**
The official Build Session FAQ states the bar exactly: *"a valid environment
screenshot from your active platform console showing that your operational
application backend is running live inside an Alibaba Cloud ECS or SAS container
setup."* A Model Studio / DashScope usage page does **not** meet this bar - the
screenshot must show **compute (ECS or SAS) in the Running state** with this
backend deployed on it.

This was captured on 2026-07-06 and committed at
[`docs/proof/alibaba-workbench.png`](docs/proof/README.md): the repo was
deployed on the instance (steps 1-5: `./setup.sh docker` demo end-to-end plus a
live `scripts/qwen_smoke.py` call - `SENTINEL-QWEN-OK`), and the console
Servers view was screenshotted with the instance **Running**. A short screen
recording of the same view was captured for the Devpost form (covers the older
"short recording" wording on the main page).

The screenshot is attached to the Devpost "Proof of Deployment" question with
`llm_provider.py` as the code file, and **the instance stays running through
the judging period (Jul 10-31)** - the FAQ says an Alibaba-hosted backend
"enables live verification and direct execution testing during the validation
period" and is an explicit evaluation plus-point.

---

## Notes
- **Cost:** the model tiering in `.env.qwen.example` (qwen3.7-max for the keystone
  analysis + 13AA, qwen-plus for the high-volume ensemble/ReAct) is chosen to
  fit the $40 credit. Pin exact rates with `SIFT_PRICE_*` if you want the printed
  `$` to match the invoice.
- **Secrets:** the key lives in `.env` (git-ignored). Never commit it.
- **Region/endpoint:** international default is the Singapore compatible-mode
  endpoint; switch `DASHSCOPE_BASE_URL` for mainland China. Your API key is
  region-scoped - a Singapore (intl) key will not authenticate against the
  mainland endpoint, and vice versa.
- **Status: DEPLOYED (2026-07-06).** This runbook was executed end-to-end on an
  Alibaba Cloud **SAS** instance (Singapore, Ubuntu 24.04): repo cloned,
  `./setup.sh docker` demo ran clean, and `scripts/qwen_smoke.py` made a live
  Qwen call from the instance (`SENTINEL-QWEN-OK`). The Workbench screenshot is
  committed at [`docs/proof/`](docs/proof/) and the instance stays running
  through the judging period. Separately, two full paired investigations have
  run end-to-end on Qwen models via the same DashScope API (verified numbers in
  `QWEN-SUBMISSION.md`).
