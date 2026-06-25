# Run Sentinel Ensemble in Docker (any OS)

Run the agent on **Windows, macOS, or Linux** with nothing but Docker Desktop -
no SANS SIFT VM, no manual forensic-toolchain install. The agent, the commands,
and the trust layer are identical to the SIFT path; only the packaging differs.

> 🔒 The image **never contains a key**. `.env` and `*_API_KEY*` files are excluded
> by `.dockerignore`; you pass the key at runtime with `-e`. Evidence is mounted
> **read-only** (`:ro`), preserving chain of custody.

---

## Two image targets

| Target | Size | Contains | Use it for |
|---|---|---|---|
| `demo` | ~290 MB | Python + 4 deps | The zero-cost `--demo` (synthetic case, **no key, no evidence, no tools**) |
| `full` (default) | ~485 MB | demo + **Volatility 3, Sleuth Kit, EWF tools, YARA** | Real memory/disk investigations on Qwen |

---

## 1. Just try it (zero cost, ~30 seconds)

No API key, no evidence, no forensic tools needed.

```bash
git clone https://github.com/3sk1nt4n/Sentinel-Ensemble-Qwen.git
cd Sentinel-Ensemble-Qwen

docker build --target demo -t sentinel-qwen:demo .
docker run --rm -it sentinel-qwen:demo
```

You should see a synthetic case card ending in **"Everything verified and ready."**
That confirms the whole flow works on your machine. Press `Q` to quit.

---

## 2. A real investigation on Qwen Cloud

Build the full image (adds the forensic toolchain), then mount your evidence
**read-only** and pass your Qwen/DashScope key:

```bash
docker build -t sentinel-qwen .          # default target = full

docker run --rm -it \
  -e SIFT_LLM_PROVIDER=qwen \
  -e DASHSCOPE_API_KEY=sk-your-key \
  -e SIFT_DEFAULT_MODEL=qwen3.7-max \
  -v /path/to/your/case:/evidence:ro \
  sentinel-qwen /evidence
```

- `-v /path/to/your/case:/evidence:ro` mounts your case folder (memory image,
  disk image, logs) read-only at `/evidence` (the image's default `EVIDENCE_DIR`).
- The last argument (`/evidence`) is the case path handed to `findevil.sh`.
- **Windows (PowerShell)** path example:
  `-v C:\cases\rd01:/evidence:ro`
- **macOS/Linux** path example:
  `-v $HOME/cases/rd01:/evidence:ro`

Confirm connectivity first (optional):

```bash
docker run --rm -e SIFT_LLM_PROVIDER=qwen -e DASHSCOPE_API_KEY=sk-... \
  --entrypoint python3 sentinel-qwen scripts/qwen_smoke.py
```

### Anthropic fallback (optional)
The provider seam keeps Claude as the zero-regression default - drop the
`SIFT_LLM_PROVIDER` line and pass `-e ANTHROPIC_API_KEY=...` to run the identical
pipeline on Claude.

---

## 3. Analyzing an `.E01` disk image (needs FUSE)

Raw memory images (`.raw` / `.img` / `.vmem`) work with the plain command above -
Volatility 3 reads them directly. **Expert Witness (`.E01`) disk images** are
mounted via `ewfmount`, which needs FUSE inside the container, so add:

```bash
docker run --rm -it \
  --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined \
  -e SIFT_LLM_PROVIDER=qwen -e DASHSCOPE_API_KEY=sk-... \
  -v /path/to/your/case:/evidence:ro \
  sentinel-qwen /evidence
```

(`.E01` mounting needs these flags only because FUSE requires elevated
capabilities; the demo and pure-memory runs do not.)

---

## Scope / honest limits

- The full image covers **memory (Volatility 3)** and **disk/filesystem
  (Sleuth Kit + EWF)** plus **YARA**. The pipeline degrades gracefully when an
  optional tool is absent (its tool-health check marks it unavailable).
- **EZ Tools** (Windows registry / EVTX artifact parsing) are .NET binaries that
  ship pre-installed on the **SANS SIFT Workstation** and are *not* bundled in
  this image (licensing + size). For those specific artifact parsers, use the
  SIFT path - everything else runs the same in Docker.
- Plaso (`log2timeline`) is likewise a SIFT-native heavy add; not in the image.

For full forensic coverage out-of-the-box, the **SANS SIFT VM** path in the
[README](../README.md) remains the most complete environment. Docker is the
fastest way to *try* the agent and to run memory/disk investigations anywhere.
