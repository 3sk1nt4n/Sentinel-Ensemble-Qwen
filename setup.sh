#!/usr/bin/env bash
# =============================================================================
# setup.sh - ONE command to install + verify everything Sentinel Qwen Ensemble needs.
#            Global AI Hackathon with Qwen Cloud - Track 4 (Autopilot Agent).
#
#   ./setup.sh            guided - shows the walkthrough, asks for your evidence
#   ./setup.sh docker     build + run the zero-cost demo in Docker (no key, no evidence)
#   ./setup.sh /case      ONE line, real Docker run: image, key, flags, mount - all handled
#                         (the "run" keyword is optional: ./setup.sh run /case also works)
#   ./setup.sh --native   (contributors) native install: pip/apt deps, verify, run the demo
#   ./setup.sh --check    check only (doctor mode - no install, no sudo)
#
# The DEMO and the judge path need NO API key and NO forensic tools. Forensic
# tools (Volatility 3, Sleuth Kit, ...) are only needed for REAL evidence runs
# and are reported as OPTIONAL. A DashScope (Qwen Cloud) key is only needed for a
# LIVE run. Exit 0 = ready for the demo + tests. Non-zero = a CORE item is missing.
# =============================================================================
set -uo pipefail   # NOT -e: run ALL checks and report, never abort on the first

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

# ── arg parsing ──────────────────────────────────────────────────────────────
# Judge-facing subcommands (Docker): bare / a folder / "run" / "docker".
# Contributor native install stays reachable via the explicit --native flag.
MODE_INSTALL=0; USE_SUDO=1; DOCKER_MODE=0; RUN=0; GUIDED=0; RUN_ARGS=()
if [ "${1:-}" = "run" ]; then
  RUN=1; shift; RUN_ARGS=("$@")
elif [ "${1:-}" = "docker" ]; then
  DOCKER_MODE=1
elif [ -z "${1:-}" ]; then
  # Bare "./setup.sh" = the guided judge experience (banner + ask for evidence).
  RUN=1; GUIDED=1
elif [ "${1#-}" = "$1" ]; then
  # Any non-flag first arg is the case path - even a typo'd or still-zipped
  # one, so a bad path gets the friendly "case folder not found" message
  # instead of silently starting the contributor native install.
  RUN=1; RUN_ARGS=("$@")
else
  # Flags: --native (contributor pip/apt install + verify), --check, --no-sudo.
  MODE_INSTALL=1
  for a in "$@"; do
    case "$a" in
      --native)  MODE_INSTALL=1 ;;
      --check)   MODE_INSTALL=0; USE_SUDO=0 ;;
      --no-sudo) USE_SUDO=0 ;;
      -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    esac
  done
fi

if [ -t 1 ]; then G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; B=$'\e[1m'; C=$'\e[36m'; X=$'\e[0m'
else G=; R=; Y=; B=; C=; X=; fi
FAIL=0; WARN=0
sec()  { printf "\n${B}== %s ==${X}\n" "$1"; }
ok()   { printf "  ${G}OK${X}   %s\n" "$1"; }
warn() { printf "  ${Y}WARN${X} %s\n" "$1"; WARN=$((WARN+1)); }
bad()  { printf "  ${R}FAIL${X} %s\n" "$1"; FAIL=$((FAIL+1)); }
note() { printf "  ${B}--${X}   %s\n" "$1"; }

# The guided intro (banner + evidence guide), mirroring the Windows launcher.
show_banner() {
  printf "\n${C}  +==============================================================+${X}\n"
  printf "${C}  |                                                              |${X}\n"
  printf "${B}  |         S E N T I N E L   Q W E N   E N S E M B L E          |${X}\n"
  printf "  |        Autonomous DFIR / SOC - Qwen on Alibaba Cloud         |\n"
  printf "${C}  |                                                              |${X}\n"
  printf "  |        'Point me at your evidence. I'll do the rest.'        |\n"
  printf "${C}  |                                                              |${X}\n"
  printf "${C}  +==============================================================+${X}\n\n"
}
show_guide() {
  printf "Point me at ONE case's evidence folder - I take it from there, read-only, start to finish.\n\n"
  printf "  What to put in the folder\n"
  printf "    - Memory image    .raw .img .mem .vmem .dmp      the live RAM\n"
  printf "    - Disk image      .E01 .dd .raw .img             the drive\n"
  printf "    - Notes / PDFs / spreadsheets                    kept as context\n"
  printf "    - Archives (.zip .7z)                            I unpack them\n\n"
  printf "  What I do automatically\n"
  printf "    * tell memory / disk / documents apart by PROBING them (not by name)\n"
  printf "    * mount the disk READ-ONLY, detect the OS, check the memory is healthy\n"
  printf "    * hand you a verified case card - then you pick the depth and launch\n\n"
  printf "  Need a case? Type ${B}dc01${X} at the prompt - I download the featured public\n"
  printf "  case for you (DFIR Madness DC01, memory + disk, ~5.4 GB, one time).\n"
  printf "  More free public cases: docs/DOCKER.md.\n\n"
}
# Ask for the evidence folder (like the original onboarding). Echoes the path.
read_case_path() {
  printf "   ${C}ONBOARDING - where is this case's evidence?${X}\n" >&2
  printf "  ----------------------------------------------------\n" >&2
  printf "   Paste the FOLDER that holds this case (memory + disk + notes).\n" >&2
  printf "     Example:  /home/you/cases/my-case\n" >&2
  printf "     Tip: drag the folder into this window to paste its path.\n" >&2
  printf "     No evidence yet? Type ${B}dc01${X} - I'll download the featured public case (memory + disk, ~5.4 GB).\n" >&2
  while true; do
    printf "   ${B}path (or dc01, or Q to quit):${X} " >&2
    IFS= read -r _p || { echo ""; return; }
    _p="${_p%\"}"; _p="${_p#\"}"; _p="${_p%/}"   # strip quotes + trailing slash
    [ -z "$_p" ] && continue
    case "$_p" in q|Q) echo ""; return ;; [dD][cC]01) echo "dc01"; return ;; esac
    if [ -d "$_p" ]; then echo "$_p"; return; fi
    if [ -f "$_p" ]; then bad "that's a file - give me the FOLDER it lives in." >&2; continue; fi
    bad "not found: $_p" >&2
    printf "     Check the path and try again (or Q to quit).\n" >&2
  done
}

# =============================================================================
#  DOCKER DOCTOR - shared by the `docker` and `run` modes.
#  Missing Docker? Offer to install it (Linux, official get.docker.com script)
#  or point at Docker Desktop (macOS/Windows). Daemon down? Offer to start it.
#  No docker-group membership? Fall back to `sudo docker` automatically.
# =============================================================================
DOCKER="docker"
ensure_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    printf "  ${Y}Docker is not installed on this machine.${X}\n"
    case "$(uname -s)" in
      Linux)
        if [ -t 0 ]; then
          printf "  ${B}Install it now via Docker's official script (get.docker.com)? [Y/n] ${X}"
          read -r _ans
          case "$_ans" in
            n|N|no|NO) : ;;
            *)
              printf "  ${B}--${X}   Installing Docker (you may be asked for your sudo password)...\n"
              if curl -fsSL https://get.docker.com | sudo sh; then
                sudo systemctl enable --now docker >/dev/null 2>&1 || sudo service docker start >/dev/null 2>&1 || true
                printf "  ${G}OK${X}   Docker installed\n"
              else
                printf "  ${R}FAIL${X} automatic install failed - manual guide: https://docs.docker.com/engine/install/\n"; exit 1
              fi
              ;;
          esac
        fi
        command -v docker >/dev/null 2>&1 || {
          printf "  ${R}FAIL${X} Install Docker, then re-run this command.\n"
          printf "         One-liner: ${B}curl -fsSL https://get.docker.com | sudo sh${X}\n"
          printf "         Manual guide: https://docs.docker.com/engine/install/\n"; exit 1; }
        ;;
      Darwin)
        printf "  ${B}macOS - one-time setup:${X}\n"
        printf "    1) Download Docker Desktop:  ${B}https://www.docker.com/products/docker-desktop/${X}\n"
        printf "       (pick Apple chip or Intel chip to match your Mac)\n"
        command -v brew >/dev/null 2>&1 && printf "       or, if you have Homebrew:  ${B}brew install --cask docker${X}\n"
        printf "    2) Open ${B}Docker.app${X} once and wait for the whale icon to go steady.\n"
        printf "    3) Come back to this Terminal and re-run:  ${B}./setup.sh docker${X}\n"
        exit 1
        ;;
      *)
        printf "  ${B}Windows:${X} install Docker Desktop (WSL2 backend): ${B}https://www.docker.com/products/docker-desktop/${X}\n"
        printf "         Then re-run this command inside WSL2 or Git Bash.\n"; exit 1
        ;;
    esac
  fi
  # Daemon reachable as-is?
  docker info >/dev/null 2>&1 && { DOCKER="docker"; return 0; }
  # Not running? On Linux start it WITHOUT asking - the user launched a Docker
  # command, so starting Docker is the task, not a choice. `enable --now` also
  # turns on start-at-boot, so a rebooted box never hits this again.
  # (Docker Desktop on macOS/Windows must be started by hand.)
  if [ "$(uname -s)" = "Linux" ]; then
    printf "  ${B}--${X}   Docker daemon not running - starting it now (also enabling start-at-boot)...\n"
    sudo systemctl enable --now docker >/dev/null 2>&1 \
      || sudo systemctl start docker >/dev/null 2>&1 \
      || sudo service docker start >/dev/null 2>&1 || true
    docker info >/dev/null 2>&1 && { DOCKER="docker"; return 0; }
  fi
  # Installed + running but this user lacks docker-group access -> sudo fallback.
  if [ -t 0 ]; then _SUDO="sudo"; else _SUDO="sudo -n"; fi
  if command -v sudo >/dev/null 2>&1 && $_SUDO docker info >/dev/null 2>&1; then
    DOCKER="sudo docker"
    printf "  ${B}--${X}   using '${B}sudo docker${X}' (drop sudo later: ${B}sudo usermod -aG docker %s${X}, then re-login)\n" "${USER:-$(id -un)}"
    return 0
  fi
  printf "  ${R}FAIL${X} Docker is installed but not reachable. Start Docker Desktop (macOS/Windows)\n"
  printf "         or '${B}sudo systemctl start docker${X}' (Linux), then re-run this command.\n"
  exit 1
}

# =============================================================================
#  ONE-LINE DOCKER RUN - ./setup.sh run [--dry-run] /path/to/case
#  Builds the full toolchain image on first use, applies the verified-run
#  config (FUSE caps for .E01, SIFT_HTTP_TIMEOUT, SIFT_ALLOW_YARA), reads the
#  key from .env / env (hidden prompt otherwise), mounts evidence read-only.
# =============================================================================
if [ "$RUN" = 1 ]; then
  if [ "$GUIDED" = 1 ]; then
    show_banner
    show_guide
  else
    printf "${B}Sentinel Qwen Ensemble - one-line Docker run${X}\n"
  fi
  note "working folder: $REPO_DIR"
  note "results always land in: $REPO_DIR/sentinel-results/<case>/"

  CASE=""; PASS=()
  # First EXISTING directory wins as the case path (a stray trailing word can't
  # displace it - mirrors the setup.ps1 guard); other non-flag words are noted.
  for a in "${RUN_ARGS[@]-}"; do
    case "$a" in
      --*) PASS+=("$a") ;;
      ?*)  if [ -z "$CASE" ] || { [ ! -d "$CASE" ] && [ -d "$a" ]; }; then CASE="$a"; fi ;;
    esac
  done
  # No folder given? Ask for it (banner shown above if guided) - never dead-end.
  if [ -z "$CASE" ]; then
    [ "$GUIDED" = 1 ] || { show_banner; show_guide; }
    CASE="$(read_case_path)"
    [ -n "$CASE" ] || { printf "  Bye - nothing was run.\n"; exit 0; }
  fi
  # Magic case name: "dc01" = fetch the featured public case ourselves (DFIR
  # Madness "Stolen Szechuan Sauce" DC01, memory + disk, ~5.4 GB zipped) so the
  # user never has to hand-download evidence to try a real investigation.
  if printf '%s' "$CASE" | grep -qiE '^dc01$'; then
    # Under `sudo ./setup.sh dc01` $HOME is root's - resolve the REAL user's
    # home so the samples live (and are found) in ONE place, sudo or not.
    _real_home="$HOME"
    if [ -n "${SUDO_USER:-}" ]; then
      _real_home="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)"
      [ -d "${_real_home:-}" ] || _real_home="$HOME"
    fi
    CASE="$_real_home/cases/dc01"
    # Rescue any copy an earlier sudo run put under root's home.
    if [ "$CASE" != "$HOME/cases/dc01" ] && [ -d "$HOME/cases/dc01" ]; then
      mkdir -p "$CASE"
      find "$HOME/cases/dc01" -maxdepth 1 -type f -exec mv -n {} "$CASE"/ \; 2>/dev/null || true
      rmdir "$HOME/cases/dc01" 2>/dev/null || true
    fi
    mkdir -p "$CASE"
    # Heal FIRST, decide second: flatten any nested layout (the E01 zip nests
    # its segments under E01-DC01/, which the top-level case scanner cannot
    # see; older runs left it that way). Idempotent - a flat folder is a no-op.
    find "$CASE" -mindepth 2 -type f -exec mv -f {} "$CASE"/ \; 2>/dev/null || true
    find "$CASE" -mindepth 1 -type d -empty -delete 2>/dev/null || true
    # Give the pair a SHARED host token so the engine pairs memory + disk into
    # ONE case card (the public sample's names share no common token). Rename
    # only - content untouched, hashes unchanged; EWF family kept consistent.
    ( cd "$CASE" 2>/dev/null || exit 0
      for s in *.[Ee][0-9][0-9]; do
        [ -e "$s" ] || continue
        case "$s" in dc01-cdrive.*) continue ;; esac
        mv -f "$s" "dc01-cdrive.${s##*.}" 2>/dev/null || true
      done
      for f in *.mem; do
        [ -e "$f" ] || continue
        case "$f" in dc01-memory.*) continue ;; esac
        mv -f "$f" "dc01-memory.mem" 2>/dev/null || true
        break
      done ) || true
    # "Installed" means BOTH halves of the pair are present and extracted.
    _dc01_complete() { ls "$CASE"/*.mem >/dev/null 2>&1 && ls "$CASE"/*.[Ee]01 >/dev/null 2>&1; }
    if _dc01_complete; then
      # Leftover zips would be RE-EXTRACTED by the onboarding (it unpacks
      # archives), making every image appear twice - remove them here too.
      rm -f "$CASE"/DC01-memory.zip "$CASE"/DC01-E01.zip 2>/dev/null || true
      ok "featured case already installed (memory + disk found) - skipping the download"
    else
      sec "Downloading the featured public case (DFIR Madness DC01: memory + disk pair, ~5.4 GB - one time)"
      command -v unzip >/dev/null 2>&1 || sudo apt-get install -y unzip >/dev/null 2>&1 || true
      ( cd "$CASE" || exit 1
        for _u in https://dfirmadness.com/case001/DC01-memory.zip \
                  https://dfirmadness.com/case001/DC01-E01.zip; do
          wget -c "$_u" || curl -fLO -C - "$_u" || exit 1
        done
        unzip -o -j DC01-memory.zip && unzip -o -j DC01-E01.zip ) \
        || { bad "download/unpack failed - check the network and re-run the same command (downloads resume)"; exit 1; }
      [ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$CASE" 2>/dev/null || true
      if _dc01_complete; then
        # The extracted pair is verified - the zips are dead weight now (~5 GB).
        rm -f "$CASE"/DC01-memory.zip "$CASE"/DC01-E01.zip 2>/dev/null || true
        ok "evidence ready: $CASE (zips removed after verification, ~5 GB freed)"
      else
        bad "evidence incomplete after download - re-run the same command (downloads resume)"; exit 1
      fi
    fi
  fi
  if [ ! -d "$CASE" ]; then
    bad "case folder not found: $CASE"
    printf "  If your download is still a .zip, unzip it first, then use the FOLDER.\n"
    printf "  ${C}Easiest: run just  ./setup.sh  and drag the folder in when it asks.${X}\n"
    printf "  ${C}No evidence at all?  ./setup.sh dc01  downloads the featured public case.${X}\n"
    exit 2
  fi
  CASE="$(cd "$CASE" && pwd)"
  ensure_docker

  # OOM guard: cheap cloud tiers get the pipeline SIGKILLed (exit -9) at the
  # report step when RAM runs out. With < 8 GB RAM and no swap, add an 8 GB
  # swapfile ONCE (persisted in fstab) so the kernel pages instead of killing.
  if [ "$(uname -s)" = "Linux" ]; then
    _mem_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
    _swap_kb=$(awk '/SwapTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
    if [ "${_mem_kb:-0}" -gt 0 ] && [ "${_mem_kb:-0}" -lt 8000000 ] && [ "${_swap_kb:-0}" -lt 2000000 ]; then
      note "small-RAM box detected - adding an 8 GB swapfile once so the run cannot be OOM-killed"
      if [ ! -f /swapfile ]; then
        sudo fallocate -l 8G /swapfile 2>/dev/null \
          || sudo dd if=/dev/zero of=/swapfile bs=1M count=8192 status=none 2>/dev/null || true
        sudo chmod 600 /swapfile 2>/dev/null || true
        sudo mkswap /swapfile >/dev/null 2>&1 || true
      fi
      sudo swapon /swapfile 2>/dev/null || true
      grep -q '^/swapfile' /etc/fstab 2>/dev/null \
        || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null 2>&1 || true
    fi
  fi

  # Always build (never just reuse): Docker's layer cache makes this a ~2s no-op
  # when nothing changed, but a plain reuse would silently run a STALE image
  # (e.g. an older build from before a fix). First build ~15 min; later ones instant.
  if $DOCKER image inspect sentinel-qwen >/dev/null 2>&1; then
    sec "Checking the toolchain image is up to date (instant if unchanged)"
  else
    sec "Building the full toolchain image (first time, ~15 min - later runs are instant)"
  fi
  $DOCKER build -t sentinel-qwen . || { printf "  ${R}FAIL${X} build failed (see above)\n"; exit 1; }
  ok "image ready: sentinel-qwen"

  # config: pick the first REAL key - environment -> .env -> API_KEY.txt - and
  # never let a leftover placeholder beat a real key (README "Order & self-healing").
  _is_real_key() { case "${1:-}" in ""|*your-*key*|*xxxxxxxx*|sk-...*) return 1 ;; *) return 0 ;; esac; }
  _env_ds="${DASHSCOPE_API_KEY:-}"; _env_qw="${QWEN_API_KEY:-}"
  [ -f .env ] && { set -a; . ./.env 2>/dev/null || true; set +a; }
  _is_real_key "$_env_ds" && DASHSCOPE_API_KEY="$_env_ds"      # real env beats .env
  _is_real_key "$_env_qw" && QWEN_API_KEY="$_env_qw"
  _is_real_key "${DASHSCOPE_API_KEY:-}" || DASHSCOPE_API_KEY=""  # placeholder = no key
  _is_real_key "${QWEN_API_KEY:-}" || QWEN_API_KEY=""
  export DASHSCOPE_API_KEY QWEN_API_KEY
  export SIFT_LLM_PROVIDER="${SIFT_LLM_PROVIDER:-qwen}"
  export SIFT_DEFAULT_MODEL="${SIFT_DEFAULT_MODEL:-qwen3.7-max}"
  export SIFT_HTTP_TIMEOUT="${SIFT_HTTP_TIMEOUT:-600}"
  export SIFT_ALLOW_YARA="${SIFT_ALLOW_YARA:-1}"
  # API_KEY.txt (visible, gitignored): created on first run, honored on later
  # runs - README key option 2. Template only; a pasted key is never written.
  if [ ! -f API_KEY.txt ]; then
    { printf '# Sentinel Qwen Ensemble - your Qwen Cloud (DashScope) API key\n'
      printf '# Replace the last line with YOUR sk-... key, then save. Gitignored -\n'
      printf '# never uploaded or committed. Or skip this file: the launcher asks at\n'
      printf '# a hidden prompt. Get a key: https://home.qwencloud.com/api-keys\n\n'
      printf 'sk-your-dashscope-key-here\n'; } > API_KEY.txt 2>/dev/null || true
    [ -n "${SUDO_USER:-}" ] && chown "$SUDO_USER" API_KEY.txt 2>/dev/null || true
  fi
  if [ "$SIFT_LLM_PROVIDER" = qwen ] && [ -z "${DASHSCOPE_API_KEY:-}${QWEN_API_KEY:-}" ] && [ -f API_KEY.txt ]; then
    _file_key="$(grep -v '^[[:space:]]*#' API_KEY.txt 2>/dev/null \
                 | grep -Eo '(^|=)sk-[A-Za-z0-9_.-]{16,}' | tail -1 | sed 's/^=//')"
    if _is_real_key "$_file_key"; then
      export DASHSCOPE_API_KEY="$_file_key"
      note "using the key from API_KEY.txt"
    fi
  fi
  if [ "$SIFT_LLM_PROVIDER" = qwen ] && [ -z "${DASHSCOPE_API_KEY:-}${QWEN_API_KEY:-}" ]; then
    case " ${PASS[*]-} " in
      *" --dry-run "*|*" --demo "*) : ;;   # no key needed
      *) printf "  ${B}DashScope API key${X} (hidden; create one: https://home.qwencloud.com/api-keys): "
         read -rs DASHSCOPE_API_KEY; printf "\n"; export DASHSCOPE_API_KEY
         # Paste once, keep forever: one Enter saves it to the gitignored .env
         # (chmod 600), so no later run on this box ever asks again. The key is
         # never echoed; decline with n for a this-session-only key.
         if [ -n "${DASHSCOPE_API_KEY:-}" ] && [ -t 0 ]; then
           printf "  Save it on this box so future runs never ask? [Y/n] "
           read -r _savekey || _savekey=Y
           case "$_savekey" in
             [nN]*) note "not saved - this session only" ;;
             *) [ -f .env ] || cp .env.qwen.example .env 2>/dev/null || : > .env
                grep -v '^DASHSCOPE_API_KEY=' .env > .env.tmp 2>/dev/null || : > .env.tmp
                printf 'DASHSCOPE_API_KEY=%s\n' "$DASHSCOPE_API_KEY" >> .env.tmp
                mv .env.tmp .env
                chmod 600 .env 2>/dev/null || true
                # under `sudo ./setup.sh` give the file back to the real user
                [ -n "${SUDO_USER:-}" ] && chown "$SUDO_USER" .env 2>/dev/null || true
                ok "saved to .env (gitignored, chmod 600) - future runs will not ask" ;;
           esac
         fi ;;
    esac
  fi

  # forward every provider/pipeline env var that is set (never baked into the image)
  ENVARGS=()
  for v in $(compgen -A variable | grep -E '^(SIFT|DASHSCOPE|QWEN|ANTHROPIC)_'); do
    [ -n "${!v:-}" ] && ENVARGS+=(-e "$v=${!v}")
  done
  # Where results land on YOUR machine (report + dashboard), inside the repo folder.
  OUT="$REPO_DIR/sentinel-results/$(basename "$CASE")"
  mkdir -p "$OUT" 2>/dev/null || true
  note "results will be saved to: $OUT"

  # Always keep stdin open (-i) so piped/scripted input reaches the prompts;
  # add a pseudo-TTY (-t) only for a real terminal (a TTY with a pipe errors).
  TTY=(-i); [ -t 0 ] && TTY=(-it)
  sec "Launching the agent on your case (evidence mounted read-only)"
  # Loop-device access (loop-control + host /dev + block-cgroup rule) lets the
  # in-container mount ladder losetup a real .E01 - without it dmpad dies with
  # "losetup failed". Evidence itself stays read-only (:ro) regardless.
  $DOCKER run --rm "${TTY[@]}" \
    --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined \
    --device /dev/loop-control --device-cgroup-rule='b 7:* rmw' -v /dev:/dev \
    "${ENVARGS[@]}" -e SIFT_PERSIST_DIR=/out \
    -v "$CASE":/evidence:ro \
    -v "$OUT":/out \
    sentinel-qwen "${PASS[@]}" /evidence
  _rc=$?
  # Container may write /out as root (sudo docker); hand it back to the user.
  [ -d "$OUT" ] && ${DOCKER%docker}chown -R "$(id -u):$(id -g)" "$OUT" 2>/dev/null || true
  # Show the ACTUAL deliverables on THIS machine + the exact open command. The
  # container's REPORTS box shows /app/reports/... (in-container); the real files
  # are here. Pick the host's opener: macOS `open`, Linux `xdg-open`.
  _html="$(ls -1 "$OUT"/summary_report_*.html 2>/dev/null | sort | tail -1)"
  _md="$(ls -1 "$OUT"/incident_report_*.md 2>/dev/null | sort | tail -1)"; [ -n "$_md" ] || _md="$OUT/report.md"
  _opener="xdg-open"; [ "$(uname)" = "Darwin" ] && _opener="open"
  if [ -n "$_html" ] || [ -s "$_md" ]; then
    printf "\n  ${G}============================================================${X}\n"
    printf "  ${G}${B} REPORTS ARE ON YOUR MACHINE${X} (ignore the /app/reports paths\n"
    printf "  ${G} above - those were inside the container). Open them here:${X}\n"
    printf "  ${G}============================================================${X}\n"
    printf "   Folder:  %s\n" "$OUT"
    [ -n "$_html" ] && printf "\n   Interactive report (opens in your browser):\n     ${C}%s \"%s\"${X}\n" "$_opener" "$_html"
    [ -s "$_md" ]   && printf "\n   Narrative report:\n     ${C}%s \"%s\"${X}\n" "$_opener" "$_md"
    # Headless server (no display): the opener cannot help - read it in place.
    if [ "$(uname)" != "Darwin" ] && [ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && [ -s "$_md" ]; then
      printf "   Headless box? Read it right here:\n     ${C}less \"%s\"${X}\n" "$_md"
    fi
    printf "\n   (or just open the folder:  %s \"%s\" )\n\n" "$_opener" "$OUT"
    # Super-friendly: auto-open the interactive report in the default browser the
    # moment the run finishes. GUI hosts only (macOS always; Linux only when a
    # display exists) so it never errors on a headless SAS/ECS/SSH box. Kill with
    # SIFT_NO_OPEN=1.
    if [ -n "$_html" ] && [ "${SIFT_NO_OPEN:-0}" != "1" ]; then
      if [ "$(uname)" = "Darwin" ] || [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
        printf "   ${G}Opening the report in your browser now...${X}\n\n"
        "$_opener" "$_html" >/dev/null 2>&1 &
      else
        printf "   ${Y}(headless box: no browser here - open the folder above on your laptop,\n    or run the open command from a desktop session)${X}\n\n"
      fi
    fi
  else
    printf "\n  ${Y}WARN${X} no report file found in %s (the run may have exited early).\n" "$OUT"
  fi
  exit $_rc
fi

# =============================================================================
#  DOCKER PATH - works on any OS, no Python/forensic install needed
# =============================================================================
if [ "$DOCKER_MODE" = 1 ]; then
  printf "${B}Sentinel Qwen Ensemble - Docker demo${X}\n"
  ensure_docker
  sec "Building the zero-cost demo image (~290 MB, one time)"
  $DOCKER build --target demo -t sentinel-qwen:demo . || { printf "  ${R}FAIL${X} build failed (see above)\n"; exit 1; }
  ok "image built: sentinel-qwen:demo"
  sec "Running the demo (no key, no evidence)"
  $DOCKER run --rm sentinel-qwen:demo || { printf "  ${R}FAIL${X} demo run failed\n"; exit 1; }
  printf "\n  ${G}${B}✅  Docker demo works.${X}\n"
  printf "  ${B}NEXT STEP - real investigation on the featured public case, ONE line.${X}\n"
  printf "  ${B}Self-updates + auto-downloads the FULL pair (memory + disk, ~5.4 GB one${X}\n"
  printf "  ${B}time), then asks: depth (model pick) -> hidden key -> FIND:${X}\n"
  printf "    ${C}curl -fsSL https://raw.githubusercontent.com/3sk1nt4n/Sentinel-Ensemble-Qwen/master/get.sh | bash -s -- dc01${X}\n"
  printf "  Have your own case folder instead?\n"
  printf "    ${C}cd \"%s\" && ./setup.sh /path/to/case${X}\n" "$REPO_DIR"
  printf "  The hidden key prompt saves your key with one Enter - never asked again.\n"
  printf "  (Get a key: https://home.qwencloud.com/api-keys · Full guide: docs/DOCKER.md)\n\n"
  exit 0
fi

# =============================================================================
#  LOCAL / NATIVE PATH (contributors + development)
# =============================================================================
printf "${B}Sentinel Qwen Ensemble - setup & health check${X}  (Track 4, Qwen Cloud)\n(%s)\n" \
  "$([ $MODE_INSTALL = 1 ] && echo 'install + verify + run demo' || echo 'verify only')"

# ── 1. Python interpreter + venv ────────────────────────────────────────────
sec "Python"
if ! command -v python3 >/dev/null 2>&1; then
  bad "python3 not found - install Python 3.10+ first"; printf "\n"; exit 1
fi
ok "python3 $(python3 -V 2>&1 | awk '{print $2}')"
VENV_DIR="$REPO_DIR/.venv"
_venv_ok() { [ -x "$VENV_DIR/bin/python" ] && "$VENV_DIR/bin/python" -m pip --version >/dev/null 2>&1; }
_mkvenv()  { rm -rf "$VENV_DIR" 2>/dev/null; python3 -m venv "$VENV_DIR" >/dev/null 2>&1; _venv_ok; }
if [ -n "${VIRTUAL_ENV:-}" ]; then
  ok "virtualenv active: $VIRTUAL_ENV"
elif _venv_ok; then
  . "$VENV_DIR/bin/activate" && ok "using project venv: $VENV_DIR"
elif [ $MODE_INSTALL = 1 ]; then
  if [ $USE_SUDO = 1 ] && command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y python3-venv >/dev/null 2>&1 || true
  fi
  if _mkvenv; then
    . "$VENV_DIR/bin/activate" && ok "created + activated project venv: $VENV_DIR"
  else
    rm -rf "$VENV_DIR" 2>/dev/null
    warn "venv unavailable (install python3-venv for an isolated env) - using the system Python instead"
  fi
else
  warn "no virtualenv active - re-run ./setup.sh --native to set one up (needs the python3-venv package)"
fi

# ── 2. Install Python deps ──────────────────────────────────────────────────
if [ $MODE_INSTALL = 1 ]; then
  sec "Installing Python dependencies (requirements.txt)"
  python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
  if python3 -m pip install -r requirements.txt; then ok "pip install -r requirements.txt"
  else
    warn "plain pip failed - retrying with --break-system-packages (PEP 668)"
    python3 -m pip install --break-system-packages -r requirements.txt \
      && ok "pip install (--break-system-packages)" \
      || bad "pip install failed - create a venv (see Python section) and re-run ./setup.sh --native"
  fi
fi

# ── 3. Verify Python packages ───────────────────────────────────────────────
sec "Python packages"
# import_name  label  REQUIRED|OPTIONAL|STRETCH  note
py_check() {
  if python3 -c "import $1" 2>/dev/null; then ok "$2 ($1)"
  elif [ "$3" = REQUIRED ]; then bad "$2 MISSING - re-run ./setup.sh --native, or: .venv/bin/pip install $2   (import $1)"
  elif [ "$3" = STRETCH ]; then note "$2 not installed - $4"
  else warn "$2 absent (optional: $4)"; fi
}
# CORE - needed for the demo, the tests, and the judge path:
py_check pydantic    pydantic        REQUIRED ""
py_check mcp         mcp             REQUIRED ""
py_check defusedxml  defusedxml      REQUIRED ""
py_check Crypto      pycryptodome    REQUIRED ""
py_check rich        rich            REQUIRED ""
py_check psutil      psutil          REQUIRED ""
py_check Evtx        python-evtx     REQUIRED ""
# OPTIONAL - the default provider is Qwen; these only matter off the demo path:
py_check anthropic   anthropic       OPTIONAL "the Anthropic FALLBACK provider only; the Qwen path does not need it (.venv/bin/pip install \".[anthropic]\")"
py_check volatility3 volatility3     OPTIONAL "needed only for REAL memory-image runs (not the demo); .venv/bin/pip install volatility3, or use SIFT's"
py_check pytsk3      pytsk3          OPTIONAL "native disk extraction for real runs; CLI fls/icat fallback exists"

# ── 4. Forensic system tools (real evidence runs only - NOT the demo) ────────
sec "Forensic tools (only for REAL evidence runs - the demo needs none)"
if [ $MODE_INSTALL = 1 ] && [ $USE_SUDO = 1 ] && command -v apt-get >/dev/null 2>&1; then
  for pkg in sleuthkit ewf-tools yara; do
    sudo apt-get install -y "$pkg" >/dev/null 2>&1 && ok "apt: $pkg" || note "apt: $pkg not installed here (verified below if present)"
  done
fi
bin_check() {
  local name="$1" fix="$2" probe="${3:-}"
  if command -v "$name" >/dev/null 2>&1; then
    if [ -n "$probe" ]; then local ver; ver=$(eval "$probe" 2>&1 | head -1 | tr -d '\r' | cut -c1-50); ok "$name  ->  ${ver:-ok}"
    else ok "$name  ($(command -v "$name"))"; fi
  else warn "$name absent (optional, real runs only) - $fix"; fi
}
bin_check vol     ".venv/bin/pip install volatility3"          ''
bin_check fls     "sudo apt install sleuthkit"        'fls -V'
bin_check ewfinfo "sudo apt install ewf-tools"        'ewfinfo -h 2>&1 | grep -m1 -i ewfinfo'
bin_check yara    "sudo apt install yara (opt-in: SIFT_ALLOW_YARA=1)" 'yara --version'

# ── 5. Qwen Cloud readiness (only needed for a LIVE run) ─────────────────────
sec "Qwen Cloud readiness (only for a live run - the demo needs no key)"
[ -f .env.qwen.example ] && ok ".env.qwen.example present (cp .env.qwen.example .env, then paste your key)" \
                          || warn ".env.qwen.example missing"
# load .env the way findevil.sh does, then look for a key
[ -f .env ] && { set -a; . ./.env 2>/dev/null || true; set +a; }
if [ -n "${DASHSCOPE_API_KEY:-}" ] || [ -n "${QWEN_API_KEY:-}" ]; then
  ok "DashScope/Qwen key detected (live runs enabled). Verify: set -a; . ./.env; set +a; python3 scripts/qwen_smoke.py"
elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  note "only an Anthropic (fallback) key is set; for the Qwen submission set DASHSCOPE_API_KEY"
else
  note "no key yet - fine for the demo. For a live Qwen run: cp .env.qwen.example .env and paste your DashScope key"
fi

# ── 6. Prove the demo runs (install mode only) ───────────────────────────────
if [ $MODE_INSTALL = 1 ] && [ $FAIL -eq 0 ]; then
  sec "Running the demo (no key, no evidence)"
  if ./findevil.sh --demo >/dev/null 2>&1; then ok "./findevil.sh --demo completed - the pipeline works end to end"
  else warn "demo did not complete cleanly - run ./findevil.sh --demo to see the message"; fi
fi

# ── Summary ─────────────────────────────────────────────────────────────────
sec "Summary"
if [ $FAIL -eq 0 ]; then
  printf "\n  ${G}${B}=============================================================${X}\n"
  printf "  ${G}${B}  OK - ready for the demo and the tests.${X}\n"
  printf "  ${G}${B}  Next:  ./findevil.sh --demo       ${X}${G}(zero cost, no key)${X}\n"
  printf "  ${G}${B}  Live:  ./findevil.sh              ${X}${G}(guided walkthrough: evidence + hidden key prompt)${X}\n"
  printf "  ${G}${B}  Live:  ./setup.sh /path/to/case  ${X}${G}(ONE line, Docker; key from .env or a hidden prompt)${X}\n"
  printf "  ${G}${B}=============================================================${X}\n"
  printf "  ${G}(no activation needed: every script finds .venv by itself, in any new shell)${X}\n"
  [ "$WARN" -gt 0 ] && printf "  (%d optional note(s) above - fine to ignore for the demo/judge path)\n" "$WARN"
  printf "\n"
  exit 0
else
  printf "\n  ${R}${B}=============================================================${X}\n"
  printf "  ${R}${B}  NOT READY - %d required item(s) missing.${X}\n" "$FAIL"
  printf "  ${R}${B}  Fix the red FAIL line(s) above, then re-run:  ./setup.sh --native${X}\n"
  printf "  ${R}${B}=============================================================${X}\n\n"
  exit 1
fi
