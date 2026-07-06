# Proof of Deployment on Alibaba Cloud

> **Status: CAPTURED (2026-07-06).** The backend is deployed and running on an
> Alibaba Cloud **Simple Application Server** (SAS) instance in **Singapore**,
> and the screenshot below shows it in the **Running** state. The instance
> stays running through the judging period (Jul 10-31; it is paid through
> **Aug 6, 2026**), so judges can live-verify.

![Alibaba Cloud console - Simple Application Server "Ubuntu-ivhq" in the Running state (Singapore, Ubuntu 24.04, 2 vCPU / 4 GiB / 50 GiB ESSD)](alibaba-workbench.png)

**What the screenshot shows** (matching the official Build Session FAQ bar,
*"a valid environment screenshot from your active platform console showing that
your operational application backend is running live inside an Alibaba Cloud
ECS or SAS container setup"*):

- the **Alibaba Cloud console** (Simple Application Server → Servers,
  Singapore / `ap-southeast-1`),
- instance **Ubuntu-ivhq** in the green **Running** state
  (Ubuntu 24.04, 2 vCPU / 4 GiB, 50 GiB ESSD, public IP assigned),
- paid through **Aug 6, 2026** - beyond the end of judging.

**What ran on that instance** (per [`../../DEPLOY-ALIBABA.md`](../../DEPLOY-ALIBABA.md)):
the repo was cloned onto the instance, `./setup.sh docker` built and ran the
demo end-to-end (banner → evidence probe → case card → "Everything verified and
ready"), and `scripts/qwen_smoke.py` made a **live Qwen call from the instance**
through the official DashScope endpoint:

```
Calling Qwen on Alibaba Cloud DashScope ...
  model    : qwen-plus
  endpoint : https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions
  OK -- reached Qwen on Alibaba Cloud.
  reply  : 'SENTINEL-QWEN-OK'
  tokens : input=20 output=8
```

> Companion evidence already in the repo: the code file
> [`../../src/sift_sentinel/llm_provider.py`](../../src/sift_sentinel/llm_provider.py)
> (hardcodes the listed Base URL `https://dashscope-intl.aliyuncs.com/compatible-mode/v1`)
> and the run metrics in [`../qwen-runs/`](../qwen-runs/)
> (each records `llm_endpoint` = that DashScope endpoint).

---

<details>
<summary>How this was captured (the runbook, kept for reproducibility)</summary>

Per the official guide, the safe screenshot target is a **compute instance in
the Running state** in the Alibaba Cloud console - **ECS** (My Resources) or
**SAS** (server card). A Model Studio / DashScope usage page does **not** meet
that bar. Steps used:

1. Provision the SAS instance (Singapore, Ubuntu, cheapest plan) - the
   official guide recommends SAS for LLM-API agents ("under 5 minutes").
2. Deploy per [`../../DEPLOY-ALIBABA.md`](../../DEPLOY-ALIBABA.md):
   `apt-get install -y git curl ca-certificates sudo` → clone →
   `./setup.sh docker` (installs Docker itself, builds, runs the demo).
3. One live call: `docker run --rm -e SIFT_LLM_PROVIDER=qwen
   -e DASHSCOPE_API_KEY=... --entrypoint python3 sentinel-qwen:demo
   scripts/qwen_smoke.py` → `SENTINEL-QWEN-OK`.
4. Capture the console Servers view with the instance **Running** (this file's
   image), plus a short screen recording of the same view (covers the "short
   recording" wording on the hackathon main page).
5. Attach the same image to the Devpost "Proof of Deployment" question and
   keep the instance running through judging.

</details>
