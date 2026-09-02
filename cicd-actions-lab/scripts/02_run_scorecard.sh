#!/usr/bin/env bash
# Runs OpenSSF Scorecard v5.5.0 against this repository as a local folder
# (--local=<folder>, confirmed against Scorecard's own cmd/root.go), scoped
# to the Dangerous-Workflow check plus Token-Permissions as a secondary
# comparison point. Entirely local/offline: no GitHub API calls, no Actions
# minutes consumed. Requires the scorecard binary on PATH:
#   go install github.com/ossf/scorecard/v5@v5.5.0
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p evidence

echo "== scorecard version =="
scorecard version | tee evidence/scorecard-version.txt

echo
echo "== scorecard --local=. --checks=Dangerous-Workflow =="
scorecard --local=. --checks=Dangerous-Workflow --show-details --format json \
  > evidence/scorecard-dangerous-workflow.json \
  2> evidence/scorecard-dangerous-workflow.stderr.txt
cat evidence/scorecard-dangerous-workflow.json
echo "wrote evidence/scorecard-dangerous-workflow.json"

echo
echo "== scorecard --local=. --checks=Token-Permissions (secondary comparison) =="
scorecard --local=. --checks=Token-Permissions --show-details --format json \
  > evidence/scorecard-token-permissions.json \
  2> evidence/scorecard-token-permissions.stderr.txt
cat evidence/scorecard-token-permissions.json
echo "wrote evidence/scorecard-token-permissions.json"

echo
echo "Done. See evidence/ for raw output."
