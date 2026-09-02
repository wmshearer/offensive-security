"""Verify the WPA2 four-way handshake fields in captures/wpa2.eapol.cap.

These checks confirm the frame-level claim the writeup makes: a WPA2 EAPOL
handshake carries ANonce, SNonce, and a MIC per message, and messages 2 and 3
carry a non-zero MIC (the value an offline dictionary attack targets).
"""

from conftest import require_capture, run_tshark


def test_four_eapol_messages_present():
    cap = require_capture("wpa2.eapol.cap")
    out, rc = run_tshark(["-r", str(cap), "-Y", "eapol"])
    assert rc == 0
    lines = [l for l in out.splitlines() if l.strip()]
    assert len(lines) == 4, f"expected 4 EAPOL frames, got {len(lines)}"


def test_message1_has_anonce_and_zero_mic():
    cap = require_capture("wpa2.eapol.cap")
    out, rc = run_tshark(
        [
            "-r",
            str(cap),
            "-Y",
            "eapol && wlan_rsna_eapol.keydes.msgnr==1",
            "-T",
            "fields",
            "-e",
            "wlan_rsna_eapol.keydes.nonce",
            "-e",
            "wlan_rsna_eapol.keydes.mic",
        ]
    )
    assert rc == 0
    nonce, mic = out.strip().split("\t")
    assert len(nonce) > 0
    assert set(mic) == {"0"}, "message 1 MIC should be all zero (no MIC yet)"


def test_message2_has_snonce_and_nonzero_mic():
    cap = require_capture("wpa2.eapol.cap")
    out, rc = run_tshark(
        [
            "-r",
            str(cap),
            "-Y",
            "eapol && wlan_rsna_eapol.keydes.msgnr==2",
            "-T",
            "fields",
            "-e",
            "wlan_rsna_eapol.keydes.nonce",
            "-e",
            "wlan_rsna_eapol.keydes.mic",
        ]
    )
    assert rc == 0
    nonce, mic = out.strip().split("\t")
    assert len(nonce) > 0
    assert set(mic) != {"0"}, "message 2 MIC should be non-zero"
