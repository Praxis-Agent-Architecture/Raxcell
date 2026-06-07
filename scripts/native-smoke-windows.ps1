$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot

function Invoke-CheckedNative {
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(Mandatory = $true)][string[]]$Arguments
  )

  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
  }
}

if (Get-Command pnpm -ErrorAction SilentlyContinue) {
  $pnpmCommand = "pnpm"
  $pnpmPrefix = @()
} elseif (Get-Command corepack -ErrorAction SilentlyContinue) {
  Invoke-CheckedNative "corepack" @("enable")
  $pnpmCommand = "corepack"
  $pnpmPrefix = @("pnpm")
} else {
  Write-Error "Raxcell smoke requires pnpm or corepack. Install Node.js 22+ and retry."
}

Invoke-CheckedNative $pnpmCommand ($pnpmPrefix + @("install", "--frozen-lockfile"))
Invoke-CheckedNative $pnpmCommand ($pnpmPrefix + @("--dir", "raxcell/sdk", "build"))
Invoke-CheckedNative $pnpmCommand ($pnpmPrefix + @("--dir", "raxcell/sdk", "smoke:windows"))
