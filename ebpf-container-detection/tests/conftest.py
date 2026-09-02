import json
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_RAW = PROJECT_ROOT / "evidence" / "raw"
EVIDENCE_GUI = PROJECT_ROOT / "evidence" / "gui"
BPF_DIR = PROJECT_ROOT / "bpf"


def read_evidence(name):
    path = EVIDENCE_RAW / name
    assert path.exists(), f"missing evidence file: {path}"
    return path.read_text()


def data_lines(text):
    """Same filtering rule harness/analyze_results.py uses: drop bpftrace's
    'Attached N probes' banner and this project's own column-header line."""
    out = []
    for ln in text.splitlines():
        if not ln.strip():
            continue
        if ln.startswith("Attached "):
            continue
        if ln.startswith("TIME "):
            continue
        out.append(ln)
    return out


@pytest.fixture(scope="session")
def analysis():
    path = PROJECT_ROOT / "evidence" / "analysis.json"
    assert path.exists(), "evidence/analysis.json missing -- run harness/analyze_results.py"
    return json.loads(path.read_text())
