#Requires -Version 5.1
<#
.SYNOPSIS
  Standalone Windows installer for hop.
.EXAMPLE
  .\scripts\install.ps1
#>
param(
    [string]$BinDir = "$env:USERPROFILE\.local\bin"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoDir = Split-Path -Parent $ScriptDir

Write-Host "==> Building hop (release)..."
cargo build --release --manifest-path (Join-Path $RepoDir "Cargo.toml")
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
Copy-Item -Force (Join-Path $RepoDir "target\release\hop.exe") (Join-Path $BinDir "hop.exe")

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$BinDir;$userPath", "User")
    Write-Host "Added $BinDir to user PATH (open a new shell to pick it up)."
}

$ver = & (Join-Path $BinDir "hop.exe") --version
Write-Host "==> Installed $(Join-Path $BinDir 'hop.exe') ($ver)"
