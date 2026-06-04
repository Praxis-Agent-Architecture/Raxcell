#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if command -v pnpm >/dev/null 2>&1; then
  pnpm_cmd=(pnpm)
elif command -v corepack >/dev/null 2>&1; then
  corepack enable
  pnpm_cmd=(corepack pnpm)
else
  echo "Raxcell smoke requires pnpm or corepack. Install Node.js 22+ and retry." >&2
  exit 1
fi

"${pnpm_cmd[@]}" install --frozen-lockfile
"${pnpm_cmd[@]}" --dir raxcell/sdk build
"${pnpm_cmd[@]}" --dir raxcell/sdk smoke:macos
