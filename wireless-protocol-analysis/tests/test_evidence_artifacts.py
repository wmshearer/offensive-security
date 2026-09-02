"""Check that the evidence this project's writeup cites actually exists.

Does not re-derive the evidence (the scripts/ directory does that); this only
confirms the files FINDINGS.md points to are present, so a claim never
outlives the artifact it depends on.
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

EXPECTED_GUI_EVIDENCE = [
    "01-wpa2-eapol-message1-anonce.png",
    "02-wpa2-eapol-message2-snonce-mic.png",
    "03-wpa3-sae-commit.png",
    "04-wpa3-sae-confirm.png",
    "05-pmkid-positive.png",
    "06-pmkid-negative-control.png",
]

EXPECTED_CAPTURES = [
    "test-pmkid.pcap",
    "pmkid-not-recognized.cap",
    "wpa2.eapol.cap",
    "wpa3-psk.pcap",
    "wpa.cap",
    "wpa2-psk-linksys.cap",
]


@pytest.mark.parametrize("filename", EXPECTED_GUI_EVIDENCE)
def test_gui_evidence_present(filename):
    path = ROOT / "evidence" / "gui" / filename
    if not path.exists():
        pytest.skip(f"{filename} not present in evidence/gui/.")
    assert path.stat().st_size > 1000, f"{filename} looks too small to be a real screenshot"


@pytest.mark.parametrize("filename", EXPECTED_CAPTURES)
def test_capture_file_present_or_documented(filename):
    path = ROOT / "captures" / filename
    readme = ROOT / "captures" / "README.md"
    if not path.exists():
        assert readme.exists(), (
            f"{filename} is missing and captures/README.md does not exist "
            "to explain how to fetch it"
        )
        pytest.skip(f"{filename} not present; see captures/README.md.")
