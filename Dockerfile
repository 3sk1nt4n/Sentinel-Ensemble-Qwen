# Sentinel Ensemble - Qwen edition - container image
#
# Two build targets:
#   demo  -> light (python + 4 deps). Runs `findevil.sh --demo`: synthetic
#            walkthrough, NO API key, NO evidence, NO forensic tools.
#   full  -> demo + the forensic toolchain (Volatility 3, Sleuth Kit, EWF
#            tools, YARA) so real memory/disk investigations run in-container.
#            This is the DEFAULT target.
#
# Build:   docker build --target demo -t sentinel-qwen:demo .
#          docker build -t sentinel-qwen .                       # full (default)
# Try it:  docker run --rm sentinel-qwen:demo                    # zero-cost demo
#
# The image NEVER contains a key: .env is excluded by .dockerignore; pass the
# key at runtime with -e DASHSCOPE_API_KEY=... (see docs/DOCKER.md).

# ---- shared base: code + python deps -------------------------------------
FROM python:3.12-slim AS base
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

# python deps first (cache-friendly)
COPY requirements.txt ./
RUN pip install -r requirements.txt

# project source
COPY . .
RUN chmod +x findevil.sh 2>/dev/null || true

# evidence mount point (config.py EVIDENCE_DIR) - mount your case here read-only
VOLUME ["/evidence"]

ENTRYPOINT ["bash", "findevil.sh"]
CMD ["--demo"]

# ---- demo target: light, just the base -----------------------------------
FROM base AS demo

# ---- full target: base + the forensic toolchain (DEFAULT) ----------------
FROM base AS full
RUN apt-get update && apt-get install -y --no-install-recommends \
        sleuthkit \
        ewf-tools \
        libewf-dev \
        yara \
        fuse3 \
        util-linux \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Volatility 3 ships the `vol` console script the pipeline calls (config.py VOL_CMD)
RUN pip install volatility3
