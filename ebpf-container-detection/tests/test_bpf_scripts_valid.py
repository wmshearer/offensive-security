"""
Tests that the bpftrace scripts and the CO-RE build artifacts are present,
syntactically well-formed, and consistent with the probes documented in
FINDINGS.md. These do NOT require root or a running container -- they check
the checked-in scripts and the checked-in build outputs, not live syscall
behavior. Live behavior is pinned by test_detection_results.py against the
evidence files.
"""
from conftest import BPF_DIR, PROJECT_ROOT


EXPECTED_BT_SCRIPTS = [
    "namespace_watch.bt",
    "mount_watch.bt",
    "capability_watch.bt",
    "ptrace_watch.bt",
    "sensitive_write_watch.bt",
]


def test_all_five_bpftrace_scripts_exist():
    for name in EXPECTED_BT_SCRIPTS:
        assert (BPF_DIR / name).exists(), f"missing {name}"


def test_bpftrace_scripts_are_nonempty_and_have_probes():
    for name in EXPECTED_BT_SCRIPTS:
        text = (BPF_DIR / name).read_text()
        assert len(text) > 200, f"{name} looks too small to be real"
        assert "tracepoint:" in text or "kprobe:" in text, f"{name} has no probe attachment"


def test_namespace_watch_hooks_unshare_not_just_clone():
    """Pins the project's central finding: the detector must watch unshare(),
    not just clone(), because that is what this host's runc actually calls."""
    text = (BPF_DIR / "namespace_watch.bt").read_text()
    assert "sys_enter_unshare" in text
    assert "unshare_flags" in text


def test_sensitive_write_watch_hooks_both_open_and_openat():
    """Pins the second documented mistake: busybox sh uses open(2), not
    openat(2), for shell redirection, so both must be hooked."""
    text = (BPF_DIR / "sensitive_write_watch.bt").read_text()
    assert "sys_enter_open\n" in text or "sys_enter_open " in text or "sys_enter_open\r\n" in text
    assert "sys_enter_openat" in text


def test_sensitive_write_watch_matches_release_agent_by_substring_not_prefix():
    """Pins the first documented mistake: matching the whole /sys/fs/cgroup/
    prefix caught systemd's own ordinary cgroup accounting writes. The fixed
    version matches the substring 'release_agent' and must not filter on a
    bare cgroup path prefix instead."""
    text = (BPF_DIR / "sensitive_write_watch.bt").read_text()
    assert 'strcontains($path, "release_agent")' in text
    # the buggy first draft filtered on this condition alone; it must not be
    # present as a live (uncommented) condition in the current script
    code_lines = [ln for ln in text.splitlines() if not ln.strip().startswith("*") and not ln.strip().startswith("//")]
    code_text = "\n".join(code_lines)
    assert "/sys/fs/cgroup/" not in code_text


def test_capability_watch_uses_a_short_allowlist_not_every_capability():
    """Pins the false-positive finding: the script must filter to specific
    capability numbers, not fire on every cap_capable() call."""
    text = (BPF_DIR / "capability_watch.bt").read_text()
    assert "arg2 ==" in text
    # must not be an unconditional kprobe:cap_capable with no filter predicate
    assert "kprobe:cap_capable\n{" not in text.replace(" ", "")


def test_ptrace_watch_distinguishes_attach_from_traceme():
    text = (BPF_DIR / "ptrace_watch.bt").read_text()
    assert "16" in text  # PTRACE_ATTACH
    assert "PTRACE_ATTACH" in text


def test_core_program_source_exists_and_uses_ringbuf():
    src = (BPF_DIR / "container_watch.bpf.c").read_text()
    assert "BPF_MAP_TYPE_RINGBUF" in src
    assert "SEC(\"tracepoint/syscalls/sys_enter_unshare\")" in src
    assert "SEC(\"kprobe/cap_capable\")" in src


def test_core_program_has_a_makefile_using_this_kernels_btf():
    makefile = (BPF_DIR / "Makefile").read_text()
    assert "vmlinux.h" in makefile
    assert "-target bpf" in makefile


def test_vmlinux_header_was_generated_not_handwritten():
    vmlinux = BPF_DIR / "vmlinux.h"
    assert vmlinux.exists()
    text = vmlinux.read_text()
    assert "__VMLINUX_H__" in text
    # a real bpftool dump is large; a stub or placeholder would not be
    assert len(text.splitlines()) > 10000
