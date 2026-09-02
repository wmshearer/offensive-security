#!/usr/bin/env bash
# Dissect the WPA2 four-way handshake in captures/wpa2.eapol.cap.
# Extracts message number, ANonce/SNonce, and MIC for each of the four EAPOL
# frames, and writes the result to evidence/wpa2_handshake_fields.txt.
#
# Idempotent: re-running overwrites the same output file with the same result.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAP="$HERE/captures/wpa2.eapol.cap"
OUT="$HERE/evidence/wpa2_handshake_fields.txt"

if [[ ! -f "$CAP" ]]; then
    echo "SKIP: $CAP not found. See captures/README.md to fetch it." >&2
    exit 0
fi

mkdir -p "$HERE/evidence"

{
    echo "# WPA2 four-way handshake field dissection"
    echo "# Source: $CAP"
    echo "# Command: tshark -r wpa2.eapol.cap -Y eapol -T fields ..."
    echo "# frame.number  msgnr  nonce  mic"
    tshark -r "$CAP" -Y eapol -T fields \
        -e frame.number \
        -e wlan_rsna_eapol.keydes.msgnr \
        -e wlan_rsna_eapol.keydes.nonce \
        -e wlan_rsna_eapol.keydes.mic
} | tee "$OUT"

echo "Wrote $OUT"
