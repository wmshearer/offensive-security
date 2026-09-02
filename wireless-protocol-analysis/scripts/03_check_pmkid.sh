#!/usr/bin/env bash
# Compare the positive PMKID capture against the negative control, and check
# aircrack-ng's own acceptance condition (key descriptor version > 0) against
# both. Writes results to evidence/pmkid_comparison.txt.
#
# Idempotent: re-running overwrites the same output file with the same result.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POS="$HERE/captures/test-pmkid.pcap"
NEG="$HERE/captures/pmkid-not-recognized.cap"
OUT="$HERE/evidence/pmkid_comparison.txt"

if [[ ! -f "$POS" || ! -f "$NEG" ]]; then
    echo "SKIP: capture files not found. See captures/README.md to fetch them." >&2
    exit 0
fi

mkdir -p "$HERE/evidence"

# pmkid-not-recognized.cap is truncated near the end (an upstream property of
# the test file, not a defect here). tshark reports this on stderr and exits
# non-zero even though every full packet before the cut point dissects fine,
# so stderr is captured into the output instead of treated as a script error.
{
    echo "# PMKID positive capture vs negative control"
    echo ""
    echo "## test-pmkid.pcap: EAPOL message 1 frame(s) and PMKID field"
    tshark -r "$POS" -Y "eapol.type==3" -T fields \
        -e frame.number -e wlan.rsn.ie.pmkid -e wlan_rsna_eapol.keydes.key_info.keydes_version
    echo ""
    echo "## pmkid-not-recognized.cap: EAPOL message 1 frames carrying a PMKID KDE"
    echo "## (present in the frame, but with key descriptor version 0)"
    tshark -r "$NEG" -Y "wlan.rsn.ie.pmkid" -T fields \
        -e frame.number -e wlan.rsn.ie.pmkid -e wlan_rsna_eapol.keydes.key_info.keydes_version \
        2>&1 || true
    echo ""
    echo "## Total EAPOL message-1 frames in the negative control capture"
    { tshark -r "$NEG" -Y "eapol.type==3 && eapol.keydes.type==2" 2>/dev/null || true; } | wc -l
} | tee "$OUT"

echo "Wrote $OUT"
