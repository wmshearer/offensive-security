import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def root():
    return ROOT


@pytest.fixture(scope="session")
def ground_truth():
    with open(ROOT / "ground-truth.yml") as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="session")
def workflows_dir():
    return ROOT / ".github" / "workflows"


@pytest.fixture(scope="session")
def all_workflow_files(workflows_dir):
    return sorted(workflows_dir.glob("*.yml"))


@pytest.fixture(scope="session")
def zizmor_default_json():
    path = ROOT / "evidence" / "zizmor-default.json"
    with open(path) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def zizmor_auditor_json():
    path = ROOT / "evidence" / "zizmor-auditor.json"
    with open(path) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def scorecard_json():
    path = ROOT / "evidence" / "scorecard-dangerous-workflow.json"
    with open(path) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def scoring_results():
    path = ROOT / "evidence" / "scoring-results.json"
    with open(path) as f:
        return json.load(f)


def zizmor_findings_flat(data):
    """Flatten zizmor's JSON into (ident, file, line) tuples."""
    out = []
    for finding in data:
        ident = finding["ident"]
        for loc in finding.get("locations", []):
            try:
                file_path = loc["symbolic"]["key"]["Local"]["verbatim_path"]
                line = loc["concrete"]["location"]["start_point"]["row"] + 1
            except KeyError:
                continue
            out.append((ident, file_path, line))
    return out
