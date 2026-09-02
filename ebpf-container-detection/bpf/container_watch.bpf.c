// SPDX-License-Identifier: GPL-2.0
//
// container_watch.bpf.c
//
// CO-RE (Compile Once, Run Everywhere) libbpf program. This is the "real"
// eBPF program the task asked for, as distinct from the bpftrace scripts in
// this directory, which are prototypes for probe discovery and quick
// iteration. This program is verifier-checked and loaded through libbpf,
// using BTF from THIS kernel (/sys/kernel/btf/vmlinux) so it does not need
// kernel headers matching an exact running kernel version at deploy time
// (that is the whole point of CO-RE).
//
// It watches two of the five behaviors the task asked for, chosen because
// together they cover both halves of the honest-measurement finding this
// project makes:
//   1. unshare(2) calls carrying CLONE_NEW* flags -- an observable event,
//      confirmed live (see bpf/namespace_watch.bt) to be exactly how this
//      host's runc creates a container's namespaces.
//   2. cap_capable() kprobe calls for a short allowlist of escape-relevant
//      capabilities -- confirmed live to be extremely noisy unfiltered, so
//      this program applies the same capability-number allowlist the
//      bpftrace prototype in bpf/capability_watch.bt does, and adds the
//      piece that matters for the "granted but never exercised" finding:
//      it can only ever report a capability CHECK that happened. A
//      capability a process holds but never calls into a privileged
//      operation for produces no cap_capable() call at all and is
//      therefore structurally invisible to this program, or to any
//      runtime detector. That is the finding, not a limitation of this
//      specific program.
//
// Events are sent to userspace over a BPF ring buffer (BPF_MAP_TYPE_RINGBUF),
// the modern (5.8+) mechanism; this kernel is 7.0.12, so ring buffers are
// available and preferred over the older BPF_MAP_TYPE_PERF_EVENT_ARRAY.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16

#define EVT_UNSHARE   1
#define EVT_CAPABLE   2

// Namespace flag bits actually used below (from linux/sched.h on this box).
#define CLONE_NEWNS      0x00020000
#define CLONE_NEWCGROUP  0x02000000
#define CLONE_NEWUTS     0x04000000
#define CLONE_NEWIPC     0x08000000
#define CLONE_NEWUSER    0x10000000
#define CLONE_NEWPID     0x20000000
#define CLONE_NEWNET     0x40000000
#define NS_FLAGS_MASK (CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | \
                       CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET)

struct event {
	__u32 type;       // EVT_UNSHARE or EVT_CAPABLE
	__u32 pid;
	__u32 cap_or_flags; // capability number for EVT_CAPABLE, raw flags for EVT_UNSHARE
	__u8  comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Same allowlist bpf/capability_watch.bt uses, numbers from
// /usr/include/linux/capability.h on this box: CAP_DAC_READ_SEARCH=2,
// CAP_SYS_MODULE=16, CAP_SYS_PTRACE=19, CAP_SYS_ADMIN=21, CAP_SYS_BOOT=22,
// CAP_MAC_ADMIN=33.
static __always_inline int cap_is_watched(int cap)
{
	return cap == 2 || cap == 16 || cap == 19 || cap == 21 || cap == 22 || cap == 33;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int handle_unshare(struct trace_event_raw_sys_enter *ctx)
{
	unsigned long flags = ctx->args[0];

	if (!(flags & NS_FLAGS_MASK))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVT_UNSHARE;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->cap_or_flags = (__u32)flags;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/cap_capable")
int BPF_KPROBE(handle_cap_capable, const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts)
{
	if (!cap_is_watched(cap))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVT_CAPABLE;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->cap_or_flags = (__u32)cap;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
