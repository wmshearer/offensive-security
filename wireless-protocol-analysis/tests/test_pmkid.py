"""Verify the PMKID positive capture and negative control.

Confirms:
- test-pmkid.pcap contains a PMKID KDE with a key descriptor version > 0
  (the condition aircrack-ng's own source checks before accepting a PMKID).
- pmkid-not-recognized.cap contains frames with a PMKID KDE present in the
  bytes, but with key descriptor version 0, which is why aircrack-ng does
  not treat them as usable: not because the PMKID bytes are absent, but
  because the version field aircrack-ng gates on is zero.
"""

from conftest import require_capture, run_tshark


def test_positive_capture_has_pmkid_with_nonzero_keydes_version():
    cap = require_capture("test-pmkid.pcap")
    out, rc = run_tshark(
        [
            "-r",
            str(cap),
            "-Y",
            "eapol.type==3",
            "-T",
            "fields",
            "-e",
            "wlan.rsn.ie.pmkid",
            "-e",
            "wlan_rsna_eapol.keydes.key_info.keydes_version",
        ]
    )
    assert rc == 0
    pmkid, keydes_version = out.strip().split("\t")
    assert len(pmkid) == 32, "PMKID should be 16 bytes (32 hex chars)"
    assert keydes_version == "2", "expected AES/HMAC-SHA1 key descriptor version"


def test_negative_control_has_pmkid_with_zero_keydes_version():
    cap = require_capture("pmkid-not-recognized.cap")
    out, rc = run_tshark(
        [
            "-r",
            str(cap),
            "-Y",
            "wlan.rsn.ie.pmkid",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "wlan.rsn.ie.pmkid",
            "-e",
            "wlan_rsna_eapol.keydes.key_info.keydes_version",
        ]
    )
    # This capture is truncated near the end (upstream property of the test
    # file), so tshark can exit non-zero even though every frame before the
    # cut point, including the ones this test reads, dissects correctly.
    rows = [l.split("\t") for l in out.strip().splitlines() if l.strip()]
    assert len(rows) >= 1, "expected at least one PMKID-bearing frame"
    for _frame, pmkid, keydes_version in rows:
        assert len(pmkid) == 32
        assert keydes_version == "0", (
            "negative control PMKID frames should have key descriptor "
            "version 0, which is why aircrack-ng does not accept them"
        )
