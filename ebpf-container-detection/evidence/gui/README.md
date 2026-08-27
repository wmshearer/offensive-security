# GUI evidence

All screenshots were captured with `termcap.sh` (from the `wshearer-site`
project's tools), which opens a real qterminal window on this machine's
actual X display and photographs only that window by its window ID
(`import -window <id>`), never the full screen or the desktop root window.
Every image below was read back with an image tool and visually confirmed
to render, and confirmed to contain no other desktop window (no Claude
conversation, no job posting, no VS Code), before being kept.

| File | What it shows | Verified by reading back |
|------|----------------|---------------------------|
| `01_bpftrace_live_container_detection.png` | The "money shot": `namespace_watch.bt` attached live, then a real `docker run alpine true` fires and the terminal prints the real `unshare()` call from `runc:[1:CHILD]` carrying all six `CLONE_NEW*` flags, plus the `setns` calls dockerd makes to enter the new namespaces. | Yes |
| `02_capability_privileged_vs_default.png` | Runtime capability-check comparison: the same `cap_capable()` capture (allowlisted to DAC_READ_SEARCH, SYS_MODULE, SYS_PTRACE, SYS_ADMIN, SYS_BOOT, MAC_ADMIN) run once against a default `docker run alpine true` and once against `docker run --privileged alpine` that mounts and unmounts a tmpfs. `mount`/`umount` calling into `CAP_SYS_ADMIN` appear only in the privileged run's own process list; the container-runtime processes (runc/containerd-shim/dockerd) look almost identical in both, which is itself part of the finding: the runtime's own setup noise dwarfs the one real signal unless you know to look for the container's own comm. | Yes |
| `03_falco_attempt_fails.png` | The real, unmodified failure of Falco 0.39.2 (`falcosecurity/falco-no-driver`, official image) attempting to start its modern eBPF probe on this kernel (7.0.12+kali-amd64): `Error: Initialization issues during scap_init`. This is not a staged failure; two independent attempts (default engine selection, and an explicit `cpus_for_each_buffer=1` tweak) failed identically, and this is documented as the honest limit of the Falco comparison rather than worked around further. | Yes |
| `04_detection_results_chart.png` | matplotlib chart built by `harness/make_chart.py` directly from `evidence/analysis.json`, which is itself computed by `harness/analyze_results.py` from the raw bpftrace captures in `evidence/raw/`. Left panel: per-technique detection outcome. Right panel: false-positive event counts per probe on 10 seconds of pure benign desktop load, log scale, real zeros relabeled and annotated rather than hidden by the log axis. | Yes |

None of these images contain a Claude conversation window, a LinkedIn/job
posting window, or a VS Code window, even though all three were open on the
desktop at capture time -- confirmed by capturing only the isolated
qterminal window ID, and by visual inspection of each PNG afterward.
