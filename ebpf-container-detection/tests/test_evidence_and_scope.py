"""
Checks the deliverable-level requirements: screenshots exist and are real
images (not zero-byte or corrupt), the Falco attempt evidence is present and
shows the documented failure, FINDINGS.md states the scope exclusions, and
no leftover containers/networks/probes were left running by this project.

The screenshot pixel checks use PIL if available; if PIL is not installed,
those specific assertions are skipped rather than failing the whole suite,
since PIL is not one of this project's declared dependencies.
"""
import json
import subprocess

import pytest

from conftest import EVIDENCE_GUI, PROJECT_ROOT

try:
    from PIL import Image
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False


EXPECTED_SCREENSHOTS = [
    "01_bpftrace_live_container_detection.png",
    "02_capability_privileged_vs_default.png",
    "03_falco_attempt_fails.png",
    "04_detection_results_chart.png",
]


def test_all_required_screenshots_exist():
    for name in EXPECTED_SCREENSHOTS:
        path = EVIDENCE_GUI / name
        assert path.exists(), f"missing screenshot: {name}"
        assert path.stat().st_size > 5000, f"{name} is suspiciously small for a real screenshot"


@pytest.mark.skipif(not HAVE_PIL, reason="PIL not installed")
def test_screenshots_are_not_blank():
    """A blank capture (the task's own definition of a failed screenshot) is
    a single solid color across the whole image. Real terminal output has
    many distinct colors from text and syntax."""
    for name in EXPECTED_SCREENSHOTS:
        img = Image.open(EVIDENCE_GUI / name).convert("RGB")
        colors = img.getcolors(maxcolors=100000)
        assert colors is not None and len(colors) > 20, (
            f"{name} has too few distinct colors ({0 if colors is None else len(colors)}) "
            f"to be real rendered terminal/chart output"
        )


def test_gui_readme_exists_and_lists_every_screenshot():
    readme = (EVIDENCE_GUI / "README.md").read_text()
    for name in EXPECTED_SCREENSHOTS:
        assert name in readme, f"{name} not documented in evidence/gui/README.md"


def test_falco_failure_evidence_exists_and_is_honest():
    falco_dir = PROJECT_ROOT / "evidence" / "falco"
    txt_files = list(falco_dir.glob("*.txt"))
    assert txt_files, "no Falco attempt output saved"
    combined = "\n".join(f.read_text() for f in txt_files)
    assert "scap_init" in combined or "Error" in combined, (
        "Falco evidence file does not show the documented initialization failure"
    )


def test_findings_states_scope_exclusions():
    findings = (PROJECT_ROOT / "FINDINGS.md").read_text()
    lowered = findings.lower()
    assert "kernel module" in lowered
    assert "not" in lowered and "kernel module" in lowered
    assert "kernel exploitation" in lowered
    assert "cap_sys_module" in lowered


def test_findings_documents_falco_result_honestly():
    findings = (PROJECT_ROOT / "FINDINGS.md").read_text()
    assert "scap_init" in findings
    assert "Falco does not run on this host" in findings


def test_no_leftover_containers_from_this_project():
    """Checks the live Docker daemon state right now. This test requires
    Docker to be reachable; if it is not, the test is skipped rather than
    failed, since a CI environment without Docker should not fail this."""
    try:
        out = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip("docker not available in this environment")
    if out.returncode != 0:
        pytest.skip("docker daemon not reachable in this environment")
    names = [n for n in out.stdout.splitlines() if n.strip()]
    project_containers = [n for n in names if "ebpf" in n.lower() or "ptrace-target" in n.lower()]
    assert project_containers == [], f"leftover containers from this project: {project_containers}"


def test_no_leftover_bpftrace_or_core_processes():
    """Uses pgrep -x against the process's own comm (not -f against the full
    command line), so a shell command that merely mentions "bpftrace" or
    "container_watch" as a string -- such as this very test running under
    a wrapper shell -- can never self-match."""
    try:
        out = subprocess.run(["pgrep", "-x", "bpftrace"], capture_output=True, text=True, timeout=10)
        out2 = subprocess.run(["pgrep", "-x", "container_watch"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        pytest.skip("pgrep not available")
    # pgrep exits 1 when nothing matches, which is the expected clean state
    assert out.returncode == 1, f"leftover bpftrace process(es):\n{out.stdout}"
    assert out2.returncode == 1, f"leftover container_watch process(es):\n{out2.stdout}"
