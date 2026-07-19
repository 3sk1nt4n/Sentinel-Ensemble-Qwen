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
    Write-Host "  |         S E N T I N E L   Q W E N   E N S E M B L E          |" -ForegroundColor White
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
    Write-Host "     No evidence yet? Type dc01 - the featured public case (memory + disk, ~5.4 GB) is downloaded for you." -ForegroundColor DarkGray
    while ($true) {
        $p = (Read-Host "   path (or dc01, or Q to quit)").Trim().Trim('"')
        if ($p -eq '') { continue }
        if ($p -eq 'q' -or $p -eq 'Q') { return $null }
        if ($p -match '^(?i)dc01$') { return 'dc01' }
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
    Write-Host "  NEXT STEP - real investigation on the featured public case, ONE line" -ForegroundColor White
    Write-Host "  (auto-downloads the FULL pair - memory + disk, ~5.4 GB one time):"
    Write-Host "    cd `"$RepoDir`"; .\setup.cmd dc01" -ForegroundColor Cyan
    Write-Host "  Have your own case?  cd `"$RepoDir`"; .\setup.cmd C:\path\to\case"
    Write-Host "  It asks for your key at a hidden prompt - one Enter saves it for good."
    Write-Host "    (Get a key: https://home.qwencloud.com/api-keys - Full guide: docs\DOCKER.md)`n"
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
    # Magic case name: "dc01" = download the featured public case (DFIR Madness
    # "Stolen Szechuan Sauce" DC01, memory + disk, ~5.4 GB zipped) for the user.
    if ($CasePath -match '^(?i)dc01$') {
        $CasePath = Join-Path $HOME 'cases\dc01'
        New-Item -ItemType Directory -Force -Path $CasePath | Out-Null
        # Heal FIRST, decide second: flatten any nested layout (the E01 zip
        # nests its segments under E01-DC01\, which the top-level case scanner
        # cannot see). Idempotent - a flat folder is a no-op.
        function Repair-Dc01Layout {
            Get-ChildItem -LiteralPath $CasePath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                Get-ChildItem -LiteralPath $_.FullName -Recurse -File | Move-Item -Destination $CasePath -Force
                Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        # "Installed" means BOTH halves of the pair are present and extracted.
        function Test-Dc01Complete {
            [bool](Get-ChildItem -LiteralPath $CasePath -Filter '*.mem' -ErrorAction SilentlyContinue) -and
            [bool](Get-ChildItem -LiteralPath $CasePath -Filter '*.E01' -ErrorAction SilentlyContinue)
        }
        Repair-Dc01Layout
        # Shared host token so the engine pairs memory + disk into ONE card.
        Get-ChildItem -LiteralPath $CasePath -File -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Name -match '\.(E\d\d)$' -and $_.BaseName -notmatch '^dc01-cdrive') {
                Move-Item -LiteralPath $_.FullName -Destination (Join-Path $CasePath "dc01-cdrive$($_.Extension)") -Force
            } elseif ($_.Extension -ieq '.mem' -and $_.BaseName -ne 'dc01-memory') {
                Move-Item -LiteralPath $_.FullName -Destination (Join-Path $CasePath 'dc01-memory.mem') -Force
            }
        }
        if (Test-Dc01Complete) {
            # Leftover zips would be RE-EXTRACTED by the onboarding (it unpacks
            # archives), making every image appear twice - remove them here too.
            Remove-Item -LiteralPath (Join-Path $CasePath 'DC01-memory.zip'), (Join-Path $CasePath 'DC01-E01.zip') -Force -ErrorAction SilentlyContinue
            Ok "featured case already installed (memory + disk found) - skipping the download"
        } else {
            Sec "Downloading the featured public case (DFIR Madness DC01: memory + disk pair, ~5.4 GB - one time)"
            foreach ($u in 'https://dfirmadness.com/case001/DC01-memory.zip',
                           'https://dfirmadness.com/case001/DC01-E01.zip') {
                $zip = Join-Path $CasePath (Split-Path $u -Leaf)
                if (-not (Test-Path -LiteralPath $zip)) {
                    Write-Host "  --   downloading $(Split-Path $u -Leaf) ..."
                    # curl.exe (ships with Windows 10+) streams and RESUMES large
                    # files; Invoke-WebRequest is the slow fallback.
                    $curlExe = Get-Command curl.exe -ErrorAction SilentlyContinue
                    if ($curlExe) {
                        & $curlExe.Source -fL --retry 3 -C - -o $zip $u
                        if ($LASTEXITCODE -ne 0) { Bad "download failed: $u (re-run to resume)"; exit 2 }
                    } else {
                        $oldPP = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
                        try { Invoke-WebRequest -Uri $u -OutFile $zip } finally { $ProgressPreference = $oldPP }
                    }
                }
                Expand-Archive -LiteralPath $zip -DestinationPath $CasePath -Force
            }
            Repair-Dc01Layout
            if (Test-Dc01Complete) {
                # The extracted pair is verified - the zips are dead weight (~5 GB).
                Remove-Item -LiteralPath (Join-Path $CasePath 'DC01-memory.zip'), (Join-Path $CasePath 'DC01-E01.zip') -Force -ErrorAction SilentlyContinue
                Ok "evidence ready: $CasePath (zips removed after verification, ~5 GB freed)"
            } else {
                Bad "evidence incomplete after download - re-run the same command"
                exit 2
            }
        }
    }
    if (-not (Test-Path -LiteralPath $CasePath -PathType Container)) {
        Bad "case folder not found: $CasePath"
        Write-Host "  That path doesn't exist. Two things to check:" -ForegroundColor Yellow
        Write-Host "    1) If your download is still a .zip, unzip it first, then use the unzipped FOLDER."
        Write-Host "    2) Point at the FOLDER (not a file) that holds the memory + disk images."
        Write-Host "  Easiest: run just  .\setup.cmd  and DRAG the folder into the window when it asks." -ForegroundColor Cyan
        Write-Host "  No evidence at all?  .\setup.cmd dc01  downloads the featured public case." -ForegroundColor Cyan
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

    # A leftover placeholder (from .env or a stale export) counts as NO key.
    foreach ($k in @('DASHSCOPE_API_KEY','QWEN_API_KEY','ANTHROPIC_API_KEY')) {
        if ($envmap[$k] -and $envmap[$k] -match 'your-.*key|xxxxxxxx|^sk-\.\.\.') { [void]$envmap.Remove($k) }
    }

    # API_KEY.txt (visible, gitignored): created on first run, honored on later
    # runs - README key option 2. Template only; a pasted key is never written.
    $keyFile = Join-Path $PSScriptRoot 'API_KEY.txt'
    if (-not (Test-Path $keyFile)) {
        @(
            '# Sentinel Qwen Ensemble - your Qwen Cloud (DashScope) API key'
            '# Replace the last line with YOUR sk-... key, then save. Gitignored -'
            '# never uploaded or committed. Or skip this file: the launcher asks at'
            '# a hidden prompt. Get a key: https://home.qwencloud.com/api-keys'
            ''
            'sk-your-dashscope-key-here'
        ) | Set-Content $keyFile
    }

    # Key: env/.env first, then API_KEY.txt, then ask once (hidden; unless dry-run).
    $provider = $envmap['SIFT_LLM_PROVIDER']
    $haveKey = $envmap['DASHSCOPE_API_KEY'] -or $envmap['QWEN_API_KEY']
    if ($provider -eq 'qwen' -and -not $haveKey -and (Test-Path $keyFile)) {
        $fileKey = Get-Content $keyFile | Where-Object { $_ -notmatch '^\s*#' } |
            Select-String -Pattern 'sk-[A-Za-z0-9_.-]{16,}' -AllMatches |
            ForEach-Object { $_.Matches.Value } | Select-Object -Last 1
        if ($fileKey -and $fileKey -notmatch 'your-.*key') {
            $envmap['DASHSCOPE_API_KEY'] = $fileKey
            Write-Host "  -- using the key from API_KEY.txt"
            $haveKey = $true
        }
    }
    if ($provider -eq 'qwen' -and -not $haveKey -and -not $DryRun) {
        Write-Host ""
        Write-Host "  DashScope API key (hidden - never shown; create one: https://home.qwencloud.com/api-keys)" -ForegroundColor White
        $secure = Read-Host "     paste it here" -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $envmap['DASHSCOPE_API_KEY'] = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        # Paste once, keep forever: one Enter saves it to the gitignored .env,
        # so no later run on this machine ever asks again.
        if ($envmap['DASHSCOPE_API_KEY']) {
            $saveKey = Read-Host "     save it on this machine so future runs never ask? [Y/n]"
            if ($saveKey -notmatch '^[nN]') {
                $envPath = Join-Path $PSScriptRoot '.env'
                if (-not (Test-Path $envPath)) {
                    $example = Join-Path $PSScriptRoot '.env.qwen.example'
                    if (Test-Path $example) { Copy-Item $example $envPath }
                    else { New-Item -ItemType File -Path $envPath | Out-Null }
                }
                $envLines = @(Get-Content $envPath | Where-Object { $_ -notmatch '^DASHSCOPE_API_KEY=' })
                $envLines += "DASHSCOPE_API_KEY=$($envmap['DASHSCOPE_API_KEY'])"
                Set-Content -Path $envPath -Value $envLines
                Ok "saved to .env (gitignored) - future runs will not ask"
            } else {
                Write-Host "  --   not saved - this session only"
            }
        }
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
        --device /dev/loop-control --device-cgroup-rule='b 7:* rmw' -v /dev:/dev `
        @envArgs `
        -v "${Case}:/evidence:ro" `
        -v "${Out}:/out" `
        sentinel-qwen @pass /evidence
    $rc = $LASTEXITCODE

    # Show the ACTUAL deliverables on THIS machine + the exact open command.
    # (The container's REPORTS box shows /app/reports/... - those are INSIDE the
    # container. The real files are here, and `explorer` opens them with your default app.)
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
            Write-Host "     explorer `"$($html.FullName)`"" -ForegroundColor Cyan
        }
        if ($md) {
            Write-Host "`n   Narrative report:" -ForegroundColor White
            Write-Host "     explorer `"$($md.FullName)`"" -ForegroundColor Cyan
        }
        Write-Host "`n   (or just open the folder:  explorer `"$Out`" )`n"
        # Super-friendly: auto-open the interactive report in the default browser
        # the moment the run finishes. Windows is always a desktop session, so
        # this is safe. Kill with $env:SIFT_NO_OPEN=1.
        if ($html -and $env:SIFT_NO_OPEN -ne '1') {
            Write-Host "   Opening the report in your browser now..." -ForegroundColor Green
            Start-Process $html.FullName
        }
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
