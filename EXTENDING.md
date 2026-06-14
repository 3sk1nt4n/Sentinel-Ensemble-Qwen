# 🧩 Extending Sentinel Ensemble - add a forensic tool

The point of this hackathon is that good tooling goes back into the community. This
guide is the **as-built** contract for adding a forensic tool, grounded in the real
code (not a wishlist). A tool you add this way is auto-discoverable by the AI, typed,
shell-free, and **fails CI if you half-wire it** - so contributors can extend the
agent safely.

> **One rule above all (Rule 6):** everything you add is **universal / dataset-agnostic**.
> Detect *behavior* or OS-primitive *structure* - never hardcode a case's artifact
> names, IPs, PIDs, hashes, or observed counts. Case data lives in reports, never in
> source. A commit-time audit + `tests/test_phase_a_dispatcher.py` enforce this.

---

## The envelope every tool returns

Your function returns, at minimum:

```python
{"output": [ {...}, {...} ],   # the typed records (list of dicts)
 "record_count": <int>}        # len(output)
```

The MCP runner wraps it into the **standard envelope** -
`{tool_name, execution_time_ms, evidence_path, record_count, output}` (see
[`ARCHITECTURE.md`](ARCHITECTURE.md)). You never construct shell; you never write to
evidence; you read the read-only mount and return typed JSON.

---

## 3 required steps + 2 optional

### 1. Write the typed function  · `src/sift_sentinel/tools/`
Add a plain Python function in the matching module
(`disk_extended.py`, `memory_extended.py`, `memory_extended2.py`, …). It takes the
evidence path(s), reads read-only, and returns the envelope above. Keep records flat
and typed (one dict per observation).

```python
def parse_my_artifact(disk_mount: str) -> dict:
    """One-line what + why. No shell, read-only, typed output."""
    records = [_row(x) for x in _read(disk_mount)]
    return {"output": records, "record_count": len(records)}
```

### 2. Register it  · `coordinator._TOOL_REGISTRY`
`_TOOL_REGISTRY` maps `tool_name -> (callable, short_description)`. A tool is only
callable if it lives here **and** carries a capability (step 3). (Volatility 3 and
Sleuth Kit surfaces auto-register via `_register_dynamic_tools()`; hand-written tools
are added explicitly.)

### 3. Declare a capability  · `src/sift_sentinel/tools/capabilities.py`
**Required** - every registered tool needs a matching `_cap(...)` with all five fields:

```python
"parse_my_artifact": _cap(
    produces=["execution_history"],        # evidence types it yields
    applicable_when=["disk_present"],      # preconditions
    not_applicable_when=["linux_evidence"],# exclusions
    failure_modes=["artifact_absent"],     # known failure classes
    runtime_class="fast",                  # fast | medium | slow | background
),
```

### 4. (Optional) Add a fact compiler  · `src/sift_sentinel/analysis/evidence_db.py`
For findings to **cite** your tool and corroborate across artifacts, add a
`_c_<family>(records)` compiler (see `_c_process`, `_c_netconn`, `_c_malfind`) that
turns your records into typed facts the EvidenceDB indexes by path/hash/pid/etc.
Without one, your tool runs but its output can't back a confirmed finding.

### 5. (Optional) Add a resolver  · for EZ-Tools / external binaries
If the tool wraps an external parser, add its Step-6 resolver lambda + artifact-type
(see the `run_srumecmd` wiring in `coordinator.py`) so selection maps to the right
evidence file.

---

## The safety net - why half-wiring fails fast

`src/sift_sentinel/analysis/drift_gate.py` runs *before* the expensive AI stages and
**fails the run** on:

- a tool registered with **no capability** (or vice-versa),
- a high-value tool missing from the callable surface,
- a tool that produced records but has **no compiler** to type them
  (`missing_compiler_for_nonempty_tool`).

It's pure, deterministic, dataset-agnostic (set-consistency + structural expectations,
never hardcoded counts). So a contributor cannot silently ship a tool that the AI can
select but the pipeline can't use.

---

## Verify ritual (after every change - no exceptions)

```bash
pytest tests/ -x                               # stop on first failure
python -m py_compile src/**/*.py               # syntax
python -m sift_sentinel.coordinator --dry-run  # boot + drift-gate check
```

Gate every new *behavior* behind an env kill-switch (`SIFT_<FEATURE>`), default chosen
per the validate-first policy, and prove an A/B with the switch on vs off shows zero
new test failures. See [`ONBOARDING.md`](ONBOARDING.md) for the full contributor flow.

---

## Worked examples to copy

| You want to add… | Read this as a template |
|---|---|
| A disk/registry/log parser | `src/sift_sentinel/tools/disk_extended.py` |
| A memory (Volatility) surface | `src/sift_sentinel/tools/memory_extended.py` |
| A capability declaration | `src/sift_sentinel/tools/capabilities.py` |
| A fact compiler | `_c_process` / `_c_malfind` in `analysis/evidence_db.py` |

*Add a tool the right way and the AI can select it, the validator can check it, and a
finding can cite it - with the drift-gate guaranteeing all three stay consistent.*
