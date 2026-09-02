#!/usr/bin/env bash
# Regenerate the SBOM and scan, and the small summaries the tests read.
#
# The raw JSON is several megabytes and is gitignored; the summaries carry every
# number the writeup quotes and are committed, so the test suite works from a
# fresh clone without needing the images rebuilt first.
set -euo pipefail
cd "$(dirname "$0")/.."
IMG="${1:-inference-service:1.0}"

./syft  "$IMG" -o json > evidence/sbom.json
./grype "$IMG" -o json > evidence/grype.json

jq '{packages: (.artifacts|length),
     gguf: (.artifacts[]|select(.name=="gguf")|{name,version,type})}' \
   evidence/sbom.json > evidence/sbom-summary.json

jq '{total: (.matches|length),
     by_severity: (.matches|group_by(.vulnerability.severity)
                  |map({severity: .[0].vulnerability.severity, count: length})),
     gguf_findings: [.matches[]|select(.artifact.name=="gguf")]}' \
   evidence/grype.json > evidence/grype-summary.json

echo "wrote evidence/{sbom,grype}-summary.json"
