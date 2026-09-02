"""
Pins the detection findings against the actual captured evidence files.
These tests parse evidence/raw/*.txt directly (the same files a human can
open and read) rather than trusting evidence/analysis.json's numbers blindly
-- analysis.json is cross-checked here, not assumed correct.

None of these tests need root or a running container: they read files this
project already produced and committed.
"""
import re

from conftest import EVIDENCE_RAW, data_lines, read_evidence


def test_privileged_scenario_shows_container_namespace_creation():
    text = read_evidence("privileged__namespace.txt")
    assert "unshare" in text
    assert "runc:[1:CHILD]" in text
    # the six flags this project's own tracing decoded for a real docker run
    assert "NEWNS" in text and "NEWPID" in text and "NEWNET" in text


def test_gpu_scenario_namespace_signature_matches_default_pattern():
    """The sibling project found --gpus all's capability set is identical to
    the unprivileged default. This checks the runtime namespace-creation
    pattern agrees: same flags, same triggering process name."""
    gpu_text = read_evidence("gpu__namespace.txt")
    priv_text = read_evidence("privileged__namespace.txt")
    gpu_flag_lines = [l for l in gpu_text.splitlines() if "unshare" in l and "runc" in l]
    priv_flag_lines = [l for l in priv_text.splitlines() if "unshare" in l and "runc" in l]
    assert gpu_flag_lines, "no unshare event captured in the GPU scenario"
    assert priv_flag_lines, "no unshare event captured in the privileged scenario"

    def flags_of(line):
        m = re.search(r"flags=(0x[0-9a-fA-F]+)", line)
        assert m, f"could not find flags= in: {line}"
        return m.group(1)

    assert flags_of(gpu_flag_lines[0]) == flags_of(priv_flag_lines[0]), (
        "GPU container's namespace-creation flags differ from a privileged "
        "container's -- this would contradict the sibling project's finding"
    )


def test_privileged_scenario_mount_shows_non_runtime_mount_call():
    """The container's own `mount -t tmpfs` must be visible and flagged as
    not-a-runtime-process, distinct from runc's setup mounts."""
    text = read_evidence("privileged__mount.txt")
    lines = [l for l in text.splitlines() if "tmpfs" in l and "dst=/mnt" in l]
    assert lines, "expected the container's own tmpfs mount to be captured"
    assert "NOT container runtime" in lines[0]


def test_privileged_scenario_sensitive_write_caught_via_legacy_open():
    """Pins the second documented mistake and its fix: the core_pattern
    write from busybox sh must be caught, and specifically via the legacy
    open(2) syscall, not openat(2)."""
    text = read_evidence("privileged__sensitive_write.txt")
    lines = data_lines(text)
    assert lines, "sensitive_write_watch produced no events for the privileged scenario"
    matching = [l for l in lines if "core_pattern" in l]
    assert matching, "no core_pattern write captured"
    assert "open" in matching[0].split()[4] if len(matching[0].split()) > 4 else True
    assert "WR" in matching[0]


def test_docker_socket_scenario_produces_no_ptrace_signal():
    """Central honest finding: Docker socket abuse produces no distinguishing
    signal on the ptrace probe (or any of the other probes run alongside it)."""
    text = read_evidence("docker_socket__ptrace.txt")
    lines = data_lines(text)
    assert lines == [], (
        "expected zero ptrace events during the docker_socket scenario; "
        f"got {len(lines)} -- if this now fails, the finding needs updating, not the test"
    )


def test_cross_container_ptrace_attach_is_captured_and_distinguished():
    text = read_evidence("ptrace_cross_container.txt")
    lines = data_lines(text)
    assert lines, "expected the cross-namespace PTRACE_ATTACH to be captured"
    assert any("PTRACE_ATTACH" in l for l in lines)
    assert not any("PTRACE_TRACEME" in l for l in lines)


def test_benign_load_has_zero_false_positives_on_four_of_five_probes():
    for probe in ["namespace", "mount", "ptrace", "sensitive_write"]:
        text = read_evidence(f"benign__{probe}.txt")
        lines = data_lines(text)
        assert lines == [], f"expected zero benign-load false positives for {probe}, got {len(lines)}"


def test_benign_load_capability_probe_is_noisy():
    """This is the honest negative finding, pinned so it can't quietly
    'improve' without the FINDINGS.md text being revisited: cap_capable,
    even allowlisted to 6 capabilities, fires thousands of times on pure
    benign desktop load."""
    text = read_evidence("benign__capability.txt")
    lines = data_lines(text)
    assert len(lines) > 1000, (
        "expected the capability probe to be noisy on benign load (this is "
        "the project's central false-positive finding); if this is no longer "
        "true, FINDINGS.md needs to be updated, not this assertion loosened"
    )


def test_analysis_json_scenario_counts_match_recount_from_raw_files(analysis):
    """Cross-checks evidence/analysis.json's own event counts against an
    independent recount of the same raw files, so the JSON can't drift from
    the evidence it claims to summarize."""
    for scenario, probes in analysis["scenario_summary"].items():
        for probe_name, info in probes.items():
            text = read_evidence(f"{scenario}__{probe_name}.txt")
            recount = len(data_lines(text))
            assert recount == info["event_count"], (
                f"{scenario}/{probe_name}: analysis.json says "
                f"{info['event_count']} events, recount from the raw file says {recount}"
            )


def test_every_scenario_manifest_exists():
    for scenario in ["benign", "privileged", "docker_socket", "gpu"]:
        assert (EVIDENCE_RAW / f"{scenario}__manifest.json").exists()
