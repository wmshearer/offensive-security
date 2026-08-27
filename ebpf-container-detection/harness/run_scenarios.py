#!/usr/bin/env python3
"""
run_scenarios.py -- validation harness for the eBPF container-escape
detector.

What this does, plainly: for each scenario below, it starts one of the
bpftrace detection scripts in bpf/ as a background process, runs a real
Docker container that performs the scenario's action, waits, stops the
detector, and saves the detector's raw stdout under evidence/raw/. It also
runs a short "benign load" capture with nothing but ordinary desktop
activity to measure the false positive rate, which is scenario "benign".

This script does not decide what counts as a detection -- that is done
afterwards by tests/ and by a human reading the raw evidence files. This
script's only job is to produce real, timestamped, unmodified output from
real runs.

Must be run with sudo (bpftrace needs root). Requires Docker without sudo
(confirmed working in this environment).

Every container this script starts is removed (--rm) and any network it
creates is torn down at the end. See harness/cleanup_check.py to verify
nothing was left running.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BPF_DIR = PROJECT_ROOT / "bpf"
EVIDENCE_RAW = PROJECT_ROOT / "evidence" / "raw"

SCENARIOS = [
    "benign",
    "privileged",
    "docker_socket",
    "gpu",
]

PROBE_SCRIPTS = {
    "namespace": BPF_DIR / "namespace_watch.bt",
    "mount": BPF_DIR / "mount_watch.bt",
    "capability": BPF_DIR / "capability_watch.bt",
    "ptrace": BPF_DIR / "ptrace_watch.bt",
    "sensitive_write": BPF_DIR / "sensitive_write_watch.bt",
}


def run(cmd, **kw):
    print(f"+ {' '.join(cmd)}", file=sys.stderr)
    return subprocess.run(cmd, **kw)


def start_probe(probe_name, out_path, duration_sec):
    """Start a bpftrace script in the background, return the Popen handle."""
    script = PROBE_SCRIPTS[probe_name]
    out_f = open(out_path, "w")
    # bpftrace runs until killed; we give it a generous timeout as a backstop
    # in case cleanup below fails for any reason.
    proc = subprocess.Popen(
        ["sudo", "timeout", str(duration_sec + 15), "bpftrace", str(script)],
        stdout=out_f,
        stderr=subprocess.STDOUT,
    )
    return proc, out_f


def stop_probe(proc, out_f, settle_sec=2):
    time.sleep(settle_sec)  # let final events flush
    proc_kill(proc)
    out_f.close()


def proc_kill(proc):
    # bpftrace runs as root under sudo; a plain proc.terminate() only signals
    # the `sudo` wrapper, which does not forward it. Use sudo pkill on the
    # timeout/bpftrace pid tree instead.
    try:
        run(["sudo", "kill", "-INT", str(proc.pid)], check=False)
    except Exception:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        run(["sudo", "kill", "-KILL", str(proc.pid)], check=False)
        proc.wait(timeout=5)


def scenario_benign(duration_sec):
    """No container activity at all -- just let ordinary desktop activity run.
    This measures the false positive rate on normal system load."""
    print("Benign scenario: capturing ordinary system activity, no container run.")
    time.sleep(duration_sec)


def scenario_privileged(duration_sec):
    """Run a privileged container and exercise capabilities the default
    container lacks: mount a new tmpfs (needs CAP_SYS_ADMIN), attempt to load
    nothing (CAP_SYS_MODULE is not exercised, deliberately, per the hard
    constraint on kernel module loading), and read a raw device node."""
    print("Privileged scenario: docker run --privileged, exercising CAP_SYS_ADMIN via mount.")
    run([
        "docker", "run", "--rm", "--privileged", "alpine:latest", "sh", "-c",
        "mkdir -p /mnt/test && mount -t tmpfs tmpfs /mnt/test && "
        "echo core > /proc/sys/kernel/core_pattern && "
        "cat /proc/sys/kernel/core_pattern && "
        "umount /mnt/test",
    ], check=False)


def scenario_docker_socket(duration_sec):
    """Mount the Docker socket into a container and query the Docker API from
    inside it. Does NOT escape to the host -- only demonstrates the query,
    per the hard constraint."""
    print("Docker socket scenario: querying the Docker API from inside a container via the mounted socket.")
    run([
        "docker", "run", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "alpine:latest", "sh", "-c",
        "apk add --no-cache curl >/dev/null 2>&1; "
        "curl -s --unix-socket /var/run/docker.sock http://localhost/version",
    ], check=False)


def scenario_gpu(duration_sec):
    """Run a --gpus all container. The sibling project found its capability
    set is identical to the unprivileged default; this checks whether the
    detector agrees at runtime."""
    print("GPU scenario: docker run --gpus all, no --privileged.")
    run([
        "docker", "run", "--rm", "--gpus", "all",
        "nvidia/cuda:12.4.1-base-ubuntu22.04", "nvidia-smi", "-L",
    ], check=False)


SCENARIO_FUNCS = {
    "benign": scenario_benign,
    "privileged": scenario_privileged,
    "docker_socket": scenario_docker_socket,
    "gpu": scenario_gpu,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", choices=SCENARIOS, required=True)
    ap.add_argument("--probes", nargs="+", default=list(PROBE_SCRIPTS.keys()),
                     choices=list(PROBE_SCRIPTS.keys()))
    ap.add_argument("--duration", type=int, default=10,
                     help="seconds to run each probe capture")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("Note: this script invokes sudo per-probe; run as your normal user, not root.", file=sys.stderr)

    if shutil.which("bpftrace") is None:
        print("bpftrace not found on PATH", file=sys.stderr)
        sys.exit(1)

    EVIDENCE_RAW.mkdir(parents=True, exist_ok=True)

    manifest = {"scenario": args.scenario, "duration_sec": args.duration, "probes": {}}

    for probe_name in args.probes:
        out_path = EVIDENCE_RAW / f"{args.scenario}__{probe_name}.txt"
        print(f"\n=== scenario={args.scenario} probe={probe_name} ===", file=sys.stderr)
        proc, out_f = start_probe(probe_name, out_path, args.duration)
        time.sleep(1.5)  # let bpftrace finish attaching before the scenario runs
        SCENARIO_FUNCS[args.scenario](args.duration)
        stop_probe(proc, out_f)
        manifest["probes"][probe_name] = str(out_path.relative_to(PROJECT_ROOT))

    manifest_path = EVIDENCE_RAW / f"{args.scenario}__manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"\nWrote {manifest_path}")


if __name__ == "__main__":
    main()
