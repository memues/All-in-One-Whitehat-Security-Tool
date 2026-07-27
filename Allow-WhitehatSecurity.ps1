# SPDX-License-Identifier: MIT
# Allow-WhitehatSecurity.ps1
#
# Bypasses Windows 11 Smart App Control + Defender for the unsigned
# Whitehat Security release binary. This is a one-time setup; once
# the binary path is on the Defender exclusion list and the file
# does not have a Mark of the Web tag, SAC will let it through.
#
# Usage:
#
#   Save this script next to WhitehatSecurity.exe (in your Downloads
#   folder, for example), then right-click the script and pick
#   "Run with PowerShell". A UAC prompt will appear; click Yes.
#   The script will:
#
#     1. Locate WhitehatSecurity.exe in the script's directory
#     2. Add a Defender ExclusionPath for the .exe full path
#     3. Add a Defender ExclusionProcess for "WhitehatSecurity.exe"
#     4. Strip the Mark of the Web tag (Unblock-File)
#     5. Launch the .exe — the install prompt should now appear
#
# This is needed because the release binary is not code-signed with an
# EV certificate, so Smart App Control has no publisher reputation to
# go on. Nothing about the program requires the exclusions themselves.
#
# If you would rather not add Defender exclusions at all, the supported
# alternative is to build the exact release commit yourself:
#
#   dotnet publish WhitehatSecurity.csproj -c Release -r win-x64 `
#       --self-contained true
#
# A locally produced binary carries no Mark of the Web, so Smart App
# Control allows it without any exclusion or policy change.

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

Write-Host "=== Whitehat Security - SAC bypass helper ===" -ForegroundColor Cyan
Write-Host ""

# 1. Find the .exe in the same directory as this script
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $scriptDir "WhitehatSecurity.exe"

if (-not (Test-Path $exe)) {
    Write-Host "ERROR: WhitehatSecurity.exe not found next to this script." -ForegroundColor Red
    Write-Host "       Expected at: $exe" -ForegroundColor Red
    Write-Host ""
    Write-Host "Place this script in the same folder as the .exe and run it again." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[1/4] Found: $exe" -ForegroundColor Green

# 2. Defender exclusion - path
try {
    Add-MpPreference -ExclusionPath $exe -ErrorAction Stop
    Write-Host "[2/4] Defender path exclusion added: $exe" -ForegroundColor Green
}
catch {
    Write-Host "[2/4] Could not add path exclusion: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 3. Defender exclusion - process
try {
    Add-MpPreference -ExclusionProcess "WhitehatSecurity.exe" -ErrorAction Stop
    Write-Host "[3/4] Defender process exclusion added: WhitehatSecurity.exe" -ForegroundColor Green
}
catch {
    Write-Host "[3/4] Could not add process exclusion: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 4. Strip Mark of the Web
try {
    Unblock-File -Path $exe -ErrorAction Stop
    Write-Host "[4/4] Mark of the Web stripped" -ForegroundColor Green
}
catch {
    Write-Host "[4/4] Could not unblock file: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Setup complete - launching installer ===" -ForegroundColor Cyan
Write-Host ""

# 5. Launch the .exe. Smart App Control should now allow it.
try {
    Start-Process -FilePath $exe
    Write-Host "Launched. Click Yes on the install prompt and on UAC." -ForegroundColor Green
}
catch {
    Write-Host "Could not launch the .exe: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "If Smart App Control still blocks the launch, you can either:" -ForegroundColor Yellow
    Write-Host "  - Right-click WhitehatSecurity.exe -> Properties -> check 'Unblock'"
    Write-Host "  - Or temporarily turn off Smart App Control:"
    Write-Host "      Settings -> Privacy and security -> Windows Security ->"
    Write-Host "      App and browser control -> Smart App Control settings -> Off"
    Read-Host "Press Enter to exit"
    exit 1
}
