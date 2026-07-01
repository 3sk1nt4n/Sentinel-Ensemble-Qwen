# Verified Qwen Cloud run metrics (shipped evidence)

These two files are the **sanitized aggregate metrics** for the two full paired
(memory + disk) investigations that ran end-to-end on **Qwen models via the
Alibaba Cloud DashScope API**. They are the source of the numbers quoted in
[`../../QWEN-SUBMISSION.md`](../../QWEN-SUBMISSION.md) and
[`../../README.md`](../../README.md).

| File | Tier | Model | Confirmed | Findings | Runtime | Integrity |
|---|---|---|---|---|---|---|
| [`light-run-metrics.json`](light-run-metrics.json) | LIGHT | `qwen-plus` ×4 | **0** | 11 | 5m 37s | mem+disk MATCH |
| [`heavy-run-metrics.json`](heavy-run-metrics.json) | HEAVY | `qwen3.7-max` | **4** | 34 | 14m 44s | mem+disk MATCH |

Each file records `llm_provider: qwen`, the live `llm_endpoint`
(`https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions`), the
`model`, `disposition_counts`, `token_usage` (including DashScope
`total_cache_read`), and `integrity_match` - straight from the run's summary JSON.

**Why only aggregates?** Per the repo's **case-neutral policy**, full run outputs
(which contain case-specific IOCs: hostnames, paths, PIDs) are never committed.
These files carry only provider/model/endpoint, counts, timings, tokens, and the
integrity verdict - no case tokens. Reproduce the full run on your own evidence
with `./findevil.sh`; the demo video shows a live Qwen run end to end.

> The `llm_endpoint` in each file is itself part of the **Proof of Deployment on
> Alibaba Cloud**: it shows the run's reasoning went to the DashScope
> (Alibaba Cloud) endpoint, alongside the code file
> [`../../src/sift_sentinel/llm_provider.py`](../../src/sift_sentinel/llm_provider.py).
