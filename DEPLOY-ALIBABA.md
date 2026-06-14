# Deploying on Alibaba Cloud (Qwen Cloud) - runbook

Global AI Hackathon with Qwen Cloud - Track 4 (Autopilot Agent).

This is the turnkey path to satisfy the **Proof of Alibaba Cloud Deployment**
requirement: the agent's backend runs on **Alibaba Cloud ECS**, reasons via
**Qwen models on the Alibaba Cloud DashScope API**, and (optionally) stores
evidence/artifacts in **Alibaba Cloud OSS**.

```
                 Alibaba Cloud
  ┌───────────────────────────────────────────────┐
  │  ECS instance (Ubuntu)                         │
  │   - run_pipeline.py (the 16-step conductor)    │
  │   - forensic toolchain (Volatility 3, Sleuth   │
  │     Kit, EWF, Plaso) + the typed MCP server    │
  │            │                                   │
  │            ├──HTTPS──> DashScope API (Qwen)  ◄─┼── reasoning (llm_provider.py)
  │            │                                   │
  │            └──(opt)──> OSS bucket            ◄─┼── evidence in / report out
  └───────────────────────────────────────────────┘
```

The single code file that proves Alibaba Cloud API use is
[`src/sift_sentinel/llm_provider.py`](src/sift_sentinel/llm_provider.py) - it
issues live HTTPS calls to the DashScope endpoint.

---

## 0) Prerequisites (your Alibaba Cloud account)

- An **Alibaba Cloud** account (Qwen Cloud).
- A **DashScope / Qwen Cloud API key** - request the **$40 hackathon voucher**.
- An **ECS instance** (provisioned below).
- (Optional) an **OSS bucket** for evidence/artifact storage.

## 1) Provision the ECS instance

- Image: **Ubuntu 22.04 LTS**.
- Size: the agent copies evidence to local scratch and writes GBs of tool
  output, and memory images are large. Use **>= 8 vCPU / >= 16 GB RAM** and
  **>= 100 GB disk** as a floor; size RAM above the largest memory image you
  will analyse. (Override the storage floor with `SIFT_RUN_MIN_FREE_MB`.)
- Region: pick one near you; it sets the DashScope endpoint (see step 4).
- Open outbound HTTPS (443) so the instance can reach the DashScope API.

## 2) Install the forensic toolchain on the ECS instance

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv git \
    sleuthkit libewf-tools
# Volatility 3:
pip3 install volatility3
# Plaso (optional, for super-timeline):
sudo add-apt-repository -y ppa:gift/stable && sudo apt-get update \
    && sudo apt-get install -y plaso-tools
```
(EZ Tools run under the .NET runtime; install if you use the registry/EVTX
parsers. The pipeline degrades gracefully when a tool is absent.)

## 3) Get the code + Python deps

```bash
git clone <your-public-qwen-repo-url> Sentinel-Ensemble-Qwen
cd Sentinel-Ensemble-Qwen
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

## 4) Point it at Qwen (DashScope)

```bash
cp .env.qwen.example .env
# edit .env: set DASHSCOPE_API_KEY=...  (provider + model tiering are preset)
```
Key env (see `.env.qwen.example` for the full recommended set):
```bash
export SIFT_LLM_PROVIDER=qwen
export DASHSCOPE_API_KEY=sk-...
export SIFT_DEFAULT_MODEL=qwen-max          # qwen-plus on high-volume stages
# Mainland-China region? override the endpoint:
# export DASHSCOPE_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions
```
Smoke-test the Alibaba Cloud connection before a full run:
```bash
python3 -c "import os,sys; sys.path.insert(0,'src'); \
from sift_sentinel.llm_provider import make_llm_client; \
r=make_llm_client().messages.create(model='qwen-max', max_tokens=16, \
messages=[{'role':'user','content':'reply with OK'}]); \
print('DashScope OK:', r.content[0].text, '| tokens', r.usage.input_tokens, r.usage.output_tokens)"
```

## 5) (Optional) Evidence via Alibaba Cloud OSS

Keep evidence in an OSS bucket and pull it to the ECS scratch disk before a run
(read-only is preserved once mounted):
```bash
pip install oss2          # Alibaba Cloud OSS SDK
# or use ossutil:
ossutil cp oss://<bucket>/<case>/  /cases/evidence/<case>/ --recursive
```
Report artifacts can be pushed back to OSS after the run.

## 6) Run an investigation (on Qwen, on Alibaba Cloud)

```bash
./findevil.sh /cases/evidence/<case>
# or the direct invocation (bypasses interactive onboarding):
python3 run_pipeline.py --live --inv2-ensemble \
    --image /cases/evidence/<case>/memory.img \
    --disk  /cases/evidence/<case>/disk.E01
```
Evidence is mounted **read-only** and SHA256-fingerprinted pre/post (chain of
custody); the report lands in `reports/` (and optionally OSS).

## 7) Capture the proof-of-deployment recording

Record a short screen capture (separate from the demo video) showing:
1. The session is on the **ECS instance** (e.g. `hostname`, the Alibaba Cloud
   console, or the instance metadata).
2. A run executing, with the log lines showing **live DashScope calls** to Qwen
   (`LIVE: Calling qwen-... ` / HTTP 200 to the DashScope host).
3. The finished report.

Link that recording in the Devpost submission, and link
`src/sift_sentinel/llm_provider.py` as the code file demonstrating Alibaba Cloud
API use.

---

## Notes
- **Cost:** the model tiering in `.env.qwen.example` (qwen-max for the keystone
  analysis + 13AA, qwen-plus for the high-volume ensemble/ReAct) is chosen to
  fit the $40 credit. Pin exact rates with `SIFT_PRICE_*` if you want the printed
  `$` to match the invoice.
- **Secrets:** the key lives in `.env` (git-ignored). Never commit it.
- **Region/endpoint:** international default is the Singapore compatible-mode
  endpoint; switch `DASHSCOPE_BASE_URL` for mainland China.
- **Status:** this runbook is ready; the live Qwen run + recording are pending an
  active `DASHSCOPE_API_KEY` and ECS instance.
