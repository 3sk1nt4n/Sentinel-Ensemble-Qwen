# Proof of Deployment on Alibaba Cloud - screenshot

Devpost x Qwen Cloud requires **visual evidence** that the project ran on Alibaba
Cloud, in addition to the code-file proof. Drop the screenshot here as
**`alibaba-workbench.png`** and it will render below.

Capture, from the Alibaba Cloud console (Workbench), **one or both** of:

- **ECS** > Instances: your instance in the **Running** state (strongest - shows
  the backend deployed and running on Alibaba Cloud, not just locally). Use
  [`../../DEPLOY-ALIBABA.md`](../../DEPLOY-ALIBABA.md) to provision + run.
- **Model Studio / DashScope** > API Keys / Usage: your API key and the real Qwen
  token usage from a run (shows the reasoning backend ran on Alibaba Cloud).

Strongest single shot: run one investigation **from the ECS instance** and
capture the *Running* ECS instance plus the DashScope usage from that run.

Then attach the same image to the Devpost "Proof of Deployment" submission
question.

<!-- Once added:
![Alibaba Cloud Workbench - running resources](alibaba-workbench.png)
-->

> Companion evidence already in the repo: the code file
> [`../../src/sift_sentinel/llm_provider.py`](../../src/sift_sentinel/llm_provider.py)
> (Base URL) and the run metrics in [`../qwen-runs/`](../qwen-runs/)
> (`llm_endpoint` = the DashScope endpoint).
