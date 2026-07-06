@echo off
REM Sentinel Ensemble - Windows launcher (no PowerShell execution-policy change needed).
REM
REM   .\setup.cmd                       guided: shows the walkthrough, asks for your evidence
REM   .\setup.cmd docker                zero-cost demo (no key, no evidence, ~30 s)
REM   .\setup.cmd run C:\path\to\case   real investigation - one line does everything
REM
REM It just forwards to setup.ps1 with the execution policy bypassed for this run,
REM so nothing has to be enabled first. Needs Docker Desktop.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" %*
