#!/usr/bin/env bash
# Runs zizmor against the workflow corpus in both its default (Regular)
# persona and its Auditor persona, writing raw JSON and plain-text output to
# evidence/. This is entirely local/offline; no GitHub Actions execution
# occurs. Requires zizmor on PATH (pipx install zizmor).
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p evidence

echo "== zizmor version =="
zizmor --version | tee evidence/zizmor-version.txt

echo
echo "== zizmor, default (Regular) persona =="
# Exit code 14 is zizmor's normal "findings reported" exit status, not a
# script failure, so we don't let set -e kill the run on it.
zizmor --format json .github/workflows/ > evidence/zizmor-default.json 2> evidence/zizmor-default.stderr.txt || true
zizmor --no-progress .github/workflows/ > evidence/zizmor-default.plain.txt 2>&1 || true
echo "wrote evidence/zizmor-default.json and evidence/zizmor-default.plain.txt"

echo
echo "== zizmor, --persona=auditor (opt-in / advisory tier) =="
zizmor --persona=auditor --format json .github/workflows/ > evidence/zizmor-auditor.json 2> evidence/zizmor-auditor.stderr.txt || true
zizmor --persona=auditor --no-progress .github/workflows/ > evidence/zizmor-auditor.plain.txt 2>&1 || true
echo "wrote evidence/zizmor-auditor.json and evidence/zizmor-auditor.plain.txt"

echo
echo "Done. See evidence/ for raw output."
