import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "captures"


def capture_path(name: str) -> Path:
    return CAPTURES / name


def require_capture(name: str) -> Path:
    """Return the capture path, or skip the test if the file is absent.

    The captures directory is small enough to commit directly (see
    captures/README.md), but a fresh clone that ran into disk or fetch
    trouble should skip these tests rather than fail them.
    """
    path = capture_path(name)
    if not path.exists():
        pytest.skip(f"{name} not present in captures/. See captures/README.md.")
    return path


def run_tshark(args):
    """Run tshark and return (stdout, returncode).

    pmkid-not-recognized.cap is truncated near the end (an upstream property
    of the file), so tshark can exit non-zero even when the frames before the
    cut point dissect correctly. Callers that only look at frames before the
    truncation point should not treat that non-zero exit as a failure.
    """
    proc = subprocess.run(
        ["tshark", *args], capture_output=True, text=True, timeout=60
    )
    return proc.stdout, proc.returncode
