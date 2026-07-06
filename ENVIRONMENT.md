# Environment Dependencies

What the pipeline needs from the machine it runs on - the things that live
*outside* `requirements.txt` because they are system-level, or because the
Volatility 3 framework needs them at import time. If `./findevil.sh --demo`
prints **"Everything verified and ready."**, all of this is in place.

> 🐳 **Running the Docker image?** Everything on this page is already baked into
> the `full`/`full-plus` image ([`docs/DOCKER.md`](docs/DOCKER.md)) - nothing
> needs manual install. This page covers the **native Linux (contributor/dev)** path.

## Platform

| Component | Verified with | Notes |
|---|---|---|
| Docker image (`full`/`full-plus`) - **the run path** | Debian 12 base | every tool below pre-baked; nothing to install (see [`docs/DOCKER.md`](docs/DOCKER.md)) |
| Native Ubuntu 22.04 (contributors/dev) | Python 3.10+ | for hacking on the code + running the test suite (see [`ONBOARDING.md`](ONBOARDING.md)) |
| Python | 3.10+ (3.12 in the Docker image) | |
| Volatility 3 Framework | **2.28.0** (pinned in the Docker image) | native dev: `pip install volatility3` (2.27.0 also verified) |

## Python Packages

### pycryptodome - required for Volatility 3 credential plugins

**Why it matters:** Volatility 3's credential-extraction plugins import the
`Crypto` module. Without it, Vol3 *partially* fails to load its plugin
registry - and the failure is sneaky: several unrelated plugins return empty
output that surfaces as `"Expecting value: line 1 column 1"` JSON errors at
the MCP transport layer.

**Install:** nothing manual - it ships pinned in `requirements.txt` (and baked
into the Docker image). Repairing a bespoke environment that lost it:

    pip install pycryptodome

**Verify (should print OK):**

    python3 -c "from Crypto.Cipher import ARC4, AES; print('OK')"

**Tools that need it directly:**

- `vol_cachedump` (T1003.005 - cached domain credentials)
- `vol_hashdump`  (T1003.002 - SAM hash dumping)
- `vol_lsadump`   (T1003.004 - LSA secrets)

**Tools that need it transitively** (Vol3 registry subsystem import chain;
these previously crashed with JSON errors, now work correctly):

- `vol_psxview` (hidden-process cross-reference)
- `vol_netstat` (network connections, when the evidence supports it)
- `vol_hollowprocesses` (process-hollowing detection)
- `vol_pebmasquerade` (PEB masquerade detection)
- `vol_mftscan` (MFT record scanning - tens of thousands of records on a populated image)

## Tool-Registry Invariants (guarded by tests)

The tool surface is discovered at runtime, so exact counts grow as tools are
added - the floors below are the invariants (the registry floor is enforced by
`tests/test_commit25_crypto_dependency.py`; the advertised surface is registry
+ 9 core/meta tools by construction):

| Invariant | Floor | Measured (June 2026) |
|---|---:|---:|
| `_TOOL_REGISTRY` (discovered forensic tools) | 175 | **186** |
| MCP-advertised tools (registry + 9 core/meta) | 184 | **195** |

If the registry ever drops *below* a floor, something broke (most often the
pycryptodome dependency above) - the startup log never lies, counts are
computed at runtime. (Dependency identified during the Vol3 integration
analysis, Commit 25 - hence the guard-test file name.)

## Evidence Handling (read this once)

- Evidence is mounted **strictly read-only** and SHA256-fingerprinted before
  and after every run - the pipeline aborts loudly on any mismatch.
- Outputs are written only to the run's own state/report directories - never
  into evidence folders.
