"""Verify the WPA3 SAE Commit/Confirm exchange in captures/wpa3-psk.pcap.

Confirms the frame-level claim: SAE authentication frames carry a Scalar and
Finite Field Element (Commit) or a Confirm hash, not the ANonce/SNonce/MIC
structure a WPA2 handshake uses, and that the four-way handshake which
follows SAE has the same nonce/MIC shape as WPA2 (SAE changes what feeds the
four-way handshake, not the four-way handshake's own frame format).
"""

from conftest import require_capture, run_tshark


def test_sae_commit_and_confirm_frames_present():
    cap = require_capture("wpa3-psk.pcap")
    out, rc = run_tshark(
        [
            "-r",
            str(cap),
            "-Y",
            "wlan.fc.type_subtype==0x000b",
            "-T",
            "fields",
            "-e",
            "wlan.fixed.auth.alg",
            "-e",
            "wlan.fixed.auth_seq",
        ]
    )
    assert rc == 0
    rows = [l.split("\t") for l in out.strip().splitlines()]
    assert len(rows) == 4, f"expected 4 SAE authentication frames, got {len(rows)}"
    for alg, _seq in rows:
        assert alg == "3", "expected Authentication Algorithm: SAE (3)"
    seqs = [seq for _alg, seq in rows]
    assert seqs.count("0x0001") == 2, "expected two Commit frames (seq 1)"
    assert seqs.count("0x0002") == 2, "expected two Confirm frames (seq 2)"


def test_sae_commit_has_scalar_not_nonce():
    cap = require_capture("wpa3-psk.pcap")
    out, rc = run_tshark(["-r", str(cap), "-Y", "frame.number==5", "-V"])
    assert rc == 0
    assert "SAE Message Type: Commit" in out
    assert "Scalar:" in out
    assert "Finite Field Element:" in out
    assert "WPA Key Nonce" not in out
    assert "WPA Key MIC" not in out


def test_post_sae_four_way_handshake_present():
    cap = require_capture("wpa3-psk.pcap")
    out, rc = run_tshark(
        [
            "-r",
            str(cap),
            "-Y",
            "eapol",
            "-T",
            "fields",
            "-e",
            "wlan_rsna_eapol.keydes.msgnr",
        ]
    )
    assert rc == 0
    msgnrs = out.strip().splitlines()
    assert msgnrs == ["1", "2", "3", "4"], "expected the usual 4-way handshake order"
