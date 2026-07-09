<#
.SYNOPSIS
  Sentinel Qwen Ensemble - one-command launcher for Windows (PowerShell).

  The Windows twin of ./setup.sh. Same experience:

    .\setup.cmd                        guided: shows the walkthrough, asks for your evidence
    .\setup.cmd docker                 zero-cost demo - no key, no evidence (~30 s)
    .\setup.cmd C:\path\to\case        real investigation - one line does everything
    .\setup.cmd C:\path -DryRun        onboarding + plan only, nothing executed
    ("run" before the path is an accepted alias.)

  (Prefer PowerShell-native? .\setup.ps1 with the same arguments works too.)

  A real run builds the toolchain image on first use, reads your DashScope key from
  .env / the environment (or asks once, hidden), applies the verified-run flags,
  passes the .E01/FUSE capabilities, mounts your evidence READ-ONLY, launches the
  agent, and saves the report to sentinel-results\<case>\ on this machine.

  Requires Docker Desktop (https://www.docker.com/products/docker-desktop/).

  NOTE: this file is intentionally pure ASCII so it parses in Windows PowerShell
  5.1 regardless of file encoding. The fancy Unicode walkthrough (banner, case
  card, depth menu) comes from the container at run time.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Mode = '',

    [Parameter(Position = 1)]
    [string]$CasePath,

    [switch]$DryRun,

    # Swallow any extra words a user might paste (e.g. a trailing "pair") so the
    # script guides them instead of erroring with a cryptic parameter message.
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

# NOTE: 'Continue', not 'Stop'. Docker writes harmless warnings to stderr (e.g.
# "daemon is not using the default seccomp profile"); under -Stop, Windows
# PowerShell 5.1 turns that stderr text into a fake terminating error even though
# docker succeeded. We drive control flow off $LASTEXITCODE explicitly instead.
$ErrorActionPreference = 'Continue'
$RepoDir = $PSScriptRoot
# Always operate from THIS repo folder, no matter where you launched from, so
# everything (the image, your results) is in the same place every time.
Set-Location $RepoDir

function Ok   ($m) { Write-Host "  OK   $m"   -ForegroundColor Green }
function Warn ($m) { Write-Host "  WARN $m"   -ForegroundColor Yellow }
function Bad  ($m) { Write-Host "  FAIL $m"   -ForegroundColor Red }
function Note ($m) { Write-Host "  --   $m"   -ForegroundColor Cyan }
function Sec  ($m) { Write-Host "`n== $m ==" -ForegroundColor White }

function Show-Banner {
    Write-Host ""
    Write-Host "  +==============================================================+" -ForegroundColor Cyan
    Write-Host "  |                                                              |" -ForegroundColor Cyan
    Write-Host "  |              S E N T I N E L   E N S E M B L E               |" -ForegroundColor White
    Write-Host "  |        Autonomous DFIR / SOC - Qwen on Alibaba Cloud         |" -ForegroundColor Gray
    Write-Host "  |                                                              |" -ForegroundColor Cyan
    Write-Host "  |        'Point me at your evidence. I'll do the rest.'        |" -ForegroundColor Gray
    Write-Host "  |                                                              |" -ForegroundColor Cyan
    Write-Host "  +==============================================================+" -ForegroundColor Cyan
    Write-Host ""
}

function Show-EvidenceGuide {
    Write-Host "Point me at ONE case's evidence folder - I take it from there, read-only, start to finish." -ForegroundColor White
    Write-Host ""
    Write-Host "  What to put in the folder"
    Write-Host "    - Memory image    .raw .img .mem .vmem .dmp      the live RAM"       -ForegroundColor Gray
    Write-Host "    - Disk image      .E01 .dd .raw .img             the drive"         -ForegroundColor Gray
    Write-Host "    - Notes / PDFs / spreadsheets                    kept as context"   -ForegroundColor Gray
    Write-Host "    - Archives (.zip .7z)                            I unpack them"     -ForegroundColor Gray
    Write-Host ""
    Write-Host "  What I do automatically"
    Write-Host "    * tell memory / disk / documents apart by PROBING them (not by name)" -ForegroundColor Gray
    Write-Host "    * mount the disk READ-ONLY, detect the OS, check the memory is healthy" -ForegroundColor Gray
    Write-Host "    * hand you a verified case card - then you pick the depth and launch"   -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Need a case? Free public Windows cases (no login) are in docs\DOCKER.md." -ForegroundColor DarkGray
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Docker doctor: a script can't install Docker Desktop (a GUI app) on Windows,
# so guide the user precisely instead of failing cryptically.
# ---------------------------------------------------------------------------
function Test-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Bad "Docker is not installed."
        Write-Host "  Install Docker Desktop (free): https://www.docker.com/products/docker-desktop/"
        Write-Host "  During install, keep the WSL2 backend enabled. Then reopen PowerShell and re-run this."
        exit 1
    }
    # Merge stderr into stdout and swallow it; only the exit code tells us if the
    # daemon is reachable (docker prints warnings to stderr even on success).
    $null = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        Bad "Docker Desktop is installed but not running."
        Write-Host "  Start Docker Desktop (wait for the whale icon to go steady), then re-run this."
        exit 1
    }
    Ok "Docker is running"
}

function Import-DotEnv {
    $envmap = @{}
    $path = Join-Path $RepoDir '.env'
    if (Test-Path $path) {
        foreach ($line in Get-Content $path) {
            $t = $line.Trim()
            if ($t -eq '' -or $t.StartsWith('#')) { continue }
            $eq = $t.IndexOf('=')
            if ($eq -lt 1) { continue }
            $k = $t.Substring(0, $eq).Trim()
            $v = $t.Substring($eq + 1)
            # Strip trailing inline comments (.env.qwen.example uses them) or a
            # model name would become "qwen3.7-max   # fallback..." -> API 400.
            $hash = $v.IndexOf(' #')
            if ($hash -ge 0) { $v = $v.Substring(0, $hash) }
            $v = $v.Trim().Trim('"').Trim("'")
            if ($k) { $envmap[$k] = $v }
        }
    }
    return $envmap
}

# Ask for the evidence folder the way the original onboarding does.
function Read-CasePath {
    Write-Host "   ONBOARDING - where is this case's evidence?" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "   Paste the FOLDER that holds this case (memory + disk + notes)."
    Write-Host "     Example:  C:\Users\You\Downloads\my-case" -ForegroundColor Gray
    Write-Host "     Tip: you can drag the folder onto this window to paste its path." -ForegroundColor DarkGray
    while ($true) {
        $p = (Read-Host "   path (or Q to quit)").Trim().Trim('"')
        if ($p -eq '') { continue }
        if ($p -eq 'q' -or $p -eq 'Q') { return $null }
        if (Test-Path -LiteralPath $p -PathType Container) { return (Resolve-Path -LiteralPath $p).Path }
        if (Test-Path -LiteralPath $p -PathType Leaf) {
            Warn "that's a file - give me the FOLDER it lives in (it should hold the memory + disk)."
            continue
        }
        Bad "not found: $p"
        Write-Host "     Check the path and try again (or Q to quit)." -ForegroundColor Gray
    }
}

# Normalize the requested mode.
$rawMode = $Mode
$Mode = $Mode.ToLower()

# Friendly shortcut: if the first word isn't a known subcommand, treat it as the
# evidence path - so ".\setup.cmd C:\path\to\case" works with no "run" keyword.
if ($Mode -ne 'docker' -and $Mode -ne 'run' -and $Mode -ne 'help' -and $Mode -ne '') {
    if (-not $CasePath) { $CasePath = $rawMode }
    $Mode = 'run'
}
# A stray trailing word (e.g. ".\setup.cmd C:\case pair") lands in $Rest; if the
# path somehow arrived there instead, pick the first folder-like token.
if ($Rest -and $Mode -eq 'run' -and -not $CasePath) {
    foreach ($r in $Rest) { if (Test-Path -LiteralPath $r -PathType Container) { $CasePath = $r; break } }
}

# ===========================================================================
#  DEMO  ->  .\setup.cmd docker
# ===========================================================================
if ($Mode -eq 'docker') {
    Write-Host "Sentinel Qwen Ensemble - Docker demo" -ForegroundColor White
    Test-Docker
    Sec "Building the zero-cost demo image (~290 MB, one time)"
    docker build --target demo -t sentinel-qwen:demo .
    if ($LASTEXITCODE -ne 0) { Bad "build failed (see above)"; exit 1 }
    Ok "image built: sentinel-qwen:demo"
    Sec "Running the demo (no key, no evidence)"
    docker run --rm -it sentinel-qwen:demo
    if ($LASTEXITCODE -ne 0) { Bad "demo run failed (see above)"; exit 1 }
    Write-Host "`n  OK  Docker demo works." -ForegroundColor Green
    Write-Host "  Real investigation - ONE line:" -ForegroundColor White
    Write-Host "    .\setup.cmd C:\path\to\case      (or just .\setup.cmd - it asks for the folder)"
    Write-Host "    (key from .env or a hidden prompt - get one at home.qwencloud.com/api-keys)"
    Write-Host "    Free public cases + full guide: docs\DOCKER.md`n"
    exit 0
}

# ===========================================================================
#  RUN (and the default guided flow)
#     .\setup.cmd                       -> banner + guide + ask for the folder
#     .\setup.cmd C:\path\to\case       -> straight to it
# ===========================================================================
if ($Mode -eq 'run' -or $Mode -eq '') {

    $guided = ($Mode -ne 'run')
    if ($guided) {
        Show-Banner
        Show-EvidenceGuide
    }
    else {
        Write-Host "Sentinel Qwen Ensemble - one-line Docker run" -ForegroundColor White
    }
    Note "working folder: $RepoDir"
    Note "results always land in: $RepoDir\sentinel-results\<case>\"

    Test-Docker

    if (-not $CasePath) {
        $CasePath = Read-CasePath
        if (-not $CasePath) { Write-Host "  Bye - nothing was run."; exit 0 }
    }
    if (-not (Test-Path -LiteralPath $CasePath -PathType Container)) {
        Bad "case folder not found: $CasePath"
        Write-Host "  That path doesn't exist. Two things to check:" -ForegroundColor Yellow
        Write-Host "    1) If your download is still a .zip, unzip it first, then use the unzipped FOLDER."
        Write-Host "    2) Point at the FOLDER (not a file) that holds the memory + disk images."
        Write-Host "  Easiest: run just  .\setup.cmd  and DRAG the folder into the window when it asks." -ForegroundColor Cyan
        exit 2
    }
    $Case = (Resolve-Path -LiteralPath $CasePath).Path
    $CaseName = Split-Path -Leaf $Case

    # Always build (never just reuse): Docker's layer cache makes this a ~2s
    # no-op when nothing changed, but a plain reuse would silently run a STALE
    # image (e.g. an older build from before a fix). First build ~15 min.
    $null = docker image inspect sentinel-qwen 2>&1
    if ($LASTEXITCODE -eq 0) {
        Sec "Checking the toolchain image is up to date (instant if unchanged)"
    }
    else {
        Sec "Building the full toolchain image (first time, ~15 min - later runs are instant)"
    }
    docker build -t sentinel-qwen .
    if ($LASTEXITCODE -ne 0) { Bad "build failed (see above)"; exit 1 }
    Ok "image ready: sentinel-qwen"

    # Config: .env first, then verified-run defaults for anything unset.
    $envmap = Import-DotEnv
    $defaults = @{
        'SIFT_LLM_PROVIDER'  = 'qwen'
        'SIFT_DEFAULT_MODEL' = 'qwen3.7-max'
        'SIFT_HTTP_TIMEOUT'  = '600'
        'SIFT_ALLOW_YARA'    = '1'
    }
    foreach ($k in $defaults.Keys) {
        if (-not $envmap.ContainsKey($k) -and -not (Get-Item "env:$k" -ErrorAction SilentlyContinue)) {
            $envmap[$k] = $defaults[$k]
        }
    }
    # Real environment variables win over .env (same precedence as findevil.sh).
    foreach ($e in Get-ChildItem env: | Where-Object { $_.Name -match '^(SIFT|DASHSCOPE|QWEN|ANTHROPIC)_' }) {
        $envmap[$e.Name] = $e.Value
    }

    # Key: ask once (hidden) if provider is qwen and none is set (unless dry-run).
    $provider = $envmap['SIFT_LLM_PROVIDER']
    $haveKey = $envmap['DASHSCOPE_API_KEY'] -or $envmap['QWEN_API_KEY']
    if ($provider -eq 'qwen' -and -not $haveKey -and -not $DryRun) {
        Write-Host ""
        Write-Host "  DashScope API key (hidden - never shown; get one at home.qwencloud.com/api-keys)" -ForegroundColor White
        $secure = Read-Host "     paste it here" -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $envmap['DASHSCOPE_API_KEY'] = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }

    $envArgs = @()
    foreach ($k in $envmap.Keys) { if ($envmap[$k]) { $envArgs += @('-e', "$k=$($envmap[$k])") } }
    $envArgs += @('-e', 'SIFT_PERSIST_DIR=/out')

    $Out = Join-Path $RepoDir "sentinel-results\$CaseName"
    New-Item -ItemType Directory -Force -Path $Out | Out-Null
    Note "results will be saved to: $Out"

    $pass = @()
    if ($DryRun) { $pass += '--dry-run' }

    Sec "Launching the agent on your case (evidence mounted read-only)"
    # Docker Desktop's Linux backend needs the FUSE capabilities to mount .E01
    # disks (harmless for memory-only). Evidence + results are bind-mounted.
    docker run --rm -it `
        --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined `
        @envArgs `
        -v "${Case}:/evidence:ro" `
        -v "${Out}:/out" `
        sentinel-qwen @pass /evidence
    $rc = $LASTEXITCODE

    # Show the ACTUAL deliverables on THIS machine + the exact open command.
    # (The container's REPORTS box shows /app/reports/... - those are INSIDE the
    # container. The real files are here, and `ii` opens them with your default app.)
    $html = Get-ChildItem $Out -Filter 'summary_report_*.html' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    $md   = Get-ChildItem $Out -Filter 'incident_report_*.md'  -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    if (-not $md) { $md = Get-ChildItem $Out -Filter 'report.md' -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if ($html -or $md) {
        Write-Host "`n  ============================================================" -ForegroundColor Green
        Write-Host "   REPORTS ARE ON YOUR MACHINE (ignore the /app/reports paths" -ForegroundColor Green
        Write-Host "   above - those were inside the container). Open them here:" -ForegroundColor Green
        Write-Host "  ============================================================" -ForegroundColor Green
        Write-Host "   Folder:  $Out"
        if ($html) {
            Write-Host "`n   Interactive report (recommended - opens in your browser):" -ForegroundColor White
            Write-Host "     ii `"$($html.FullName)`"" -ForegroundColor Cyan
        }
        if ($md) {
            Write-Host "`n   Narrative report:" -ForegroundColor White
            Write-Host "     ii `"$($md.FullName)`"" -ForegroundColor Cyan
        }
        Write-Host "`n   (or just open the folder:  ii `"$Out`" )`n"
    }
    else {
        Write-Host "`n  WARN No report file found in $Out (the run may have exited early)." -ForegroundColor Yellow
    }
    exit $rc
}

# Unknown mode -> guide.
Show-Banner
Write-Host "  Usage:" -ForegroundColor White
Write-Host "    .\setup.cmd                        guided - shows the walkthrough, asks for your evidence"
Write-Host "    .\setup.cmd docker                 zero-cost demo (no key, no evidence, ~30 s)"
Write-Host "    .\setup.cmd C:\path\to\case    real investigation - one line does everything"
Write-Host ""
Write-Host "  Needs Docker Desktop: https://www.docker.com/products/docker-desktop/"
exit 0
