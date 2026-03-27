#!/usr/bin/env bash
# Ghost AI — Gitleaks integration runner
# Invoked by ghost_agent.py via the gitleaks tool adapter.
# Usage: ./ghost_runner.sh <path> [report_path]
set -euo pipefail

PATH_TO_SCAN="${1:-.}"
REPORT="${2:-/tmp/gitleaks_ghost.json}"

echo "[Ghost AI / Gitleaks] Scanning: ${PATH_TO_SCAN}"
gitleaks detect \
  --source "${PATH_TO_SCAN}" \
  --report-format json \
  --report-path "${REPORT}" \
  --no-git \
  --verbose

COUNT=$(python3 -c "import json,sys; d=json.load(open('${REPORT}')); print(len(d))" 2>/dev/null || echo 0)
echo "[Ghost AI / Gitleaks] Complete — ${COUNT} findings written to ${REPORT}"
