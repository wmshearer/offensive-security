#!/usr/bin/env bash
# Dissect the WPA3-SAE exchange in captures/wpa3-psk.pcap: the SAE Commit and
# Confirm authentication frames, then the subsequent four-way handshake that
# SAE feeds into. Writes results to evidence/wpa3_sae_fields.txt.
#
# Idempotent: re-running overwrites the same output file with the same result.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAP="$HERE/captures/wpa3-psk.pcap"
OUT="$HERE/evidence/wpa3_sae_fields.txt"

if [[ ! -f "$CAP" ]]; then
    echo "SKIP: $CAP not found. See captures/README.md to fetch it." >&2
    exit 0
fi

mkdir -p "$HERE/evidence"

{
    echo "# WPA3 SAE Commit/Confirm and subsequent 4-way handshake"
    echo "# Source: $CAP"
    echo ""
    echo "## Full frame list"
    tshark -r "$CAP"
    echo ""
    echo "## SAE Authentication frames (subtype 0x000b): seq, algorithm, status"
    tshark -r "$CAP" -Y "wlan.fc.type_subtype==0x000b" -T fields \
        -e frame.number -e wlan.fixed.auth.alg -e wlan.fixed.auth_seq -e wlan.fixed.status_code
    echo ""
    echo "## SAE Commit frame detail (frame 5)"
    tshark -r "$CAP" -Y "frame.number==5" -V | sed -n '/IEEE 802.11 Authentication/,/^$/p' | head -30
    echo ""
    echo "## Post-SAE four-way handshake: msgnr, nonce, mic (same structure as WPA2)"
    tshark -r "$CAP" -Y eapol -T fields \
        -e frame.number \
        -e wlan_rsna_eapol.keydes.msgnr \
        -e wlan_rsna_eapol.keydes.nonce \
        -e wlan_rsna_eapol.keydes.mic
} | tee "$OUT"

echo "Wrote $OUT"
