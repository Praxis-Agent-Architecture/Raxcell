$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot

if (Get-Command pnpm -ErrorAction SilentlyContinue) {
  $pnpmCommand = "pnpm"
  $pnpmPrefix = @()
} elseif (Get-Command corepack -ErrorAction SilentlyContinue) {
  corepack enable
  $pnpmCommand = "corepack"
  $pnpmPrefix = @("pnpm")
} else {
  Write-Error "Raxcell smoke requires pnpm or corepack. Install Node.js 22+ and retry."
}

& $pnpmCommand @pnpmPrefix install --frozen-lockfile
& $pnpmCommand @pnpmPrefix --dir raxcell/sdk build
& $pnpmCommand @pnpmPrefix --dir raxcell/sdk smoke:windows
