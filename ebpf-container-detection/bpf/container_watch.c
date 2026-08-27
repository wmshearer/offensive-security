// SPDX-License-Identifier: GPL-2.0
//
// container_watch.c -- userspace loader for container_watch.bpf.o
//
// Loads the CO-RE BPF program via libbpf's skeleton API, attaches its
// tracepoint and kprobe, and prints ring buffer events as they arrive.
// Ctrl-C (SIGINT) exits cleanly and libbpf detaches every probe on process
// exit.

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "container_watch.skel.h"

#define EVT_UNSHARE 1
#define EVT_CAPABLE 2

struct event {
	unsigned int type;
	unsigned int pid;
	unsigned int cap_or_flags;
	unsigned char comm[16];
};

static volatile sig_atomic_t stop;

static void on_sigint(int sig)
{
	(void)sig;
	stop = 1;
}

static const char *cap_name(unsigned int cap)
{
	switch (cap) {
	case 2:  return "DAC_READ_SEARCH";
	case 16: return "SYS_MODULE";
	case 19: return "SYS_PTRACE";
	case 21: return "SYS_ADMIN";
	case 22: return "SYS_BOOT";
	case 33: return "MAC_ADMIN";
	default: return "?";
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	(void)ctx;
	(void)data_sz;
	const struct event *e = data;
	char timebuf[16];
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct tm tmv;
	localtime_r(&ts.tv_sec, &tmv);
	strftime(timebuf, sizeof(timebuf), "%H:%M:%S", &tmv);

	if (e->type == EVT_UNSHARE) {
		printf("%s  unshare   pid=%-8u comm=%-16s flags=0x%x", timebuf, e->pid, e->comm, e->cap_or_flags);
		if (e->cap_or_flags & 0x00020000) printf(" NEWNS");
		if (e->cap_or_flags & 0x02000000) printf(" NEWCGROUP");
		if (e->cap_or_flags & 0x04000000) printf(" NEWUTS");
		if (e->cap_or_flags & 0x08000000) printf(" NEWIPC");
		if (e->cap_or_flags & 0x10000000) printf(" NEWUSER");
		if (e->cap_or_flags & 0x20000000) printf(" NEWPID");
		if (e->cap_or_flags & 0x40000000) printf(" NEWNET");
		printf("\n");
	} else if (e->type == EVT_CAPABLE) {
		printf("%s  capable   pid=%-8u comm=%-16s cap=%u (%s)\n",
			timebuf, e->pid, e->comm, e->cap_or_flags, cap_name(e->cap_or_flags));
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct container_watch_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;
	int duration_sec = 0; // 0 = run until Ctrl-C

	if (argc > 1)
		duration_sec = atoi(argv[1]);

	libbpf_set_print(NULL); // quiet libbpf's own log noise; errors still returned

	skel = container_watch_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load BPF skeleton (see dmesg for verifier output)\n");
		return 1;
	}

	err = container_watch_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		container_watch_bpf__destroy(skel);
		return 1;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "failed to create ring buffer\n");
		container_watch_bpf__destroy(skel);
		return 1;
	}

	signal(SIGINT, on_sigint);
	printf("container_watch attached (CO-RE, libbpf). Watching unshare() namespace flags and cap_capable().\n");
	printf("Press Ctrl-C to stop.%s\n", duration_sec ? "" : "");

	time_t start = time(NULL);
	while (!stop) {
		err = ring_buffer__poll(rb, 200 /* ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "ring_buffer__poll error: %d\n", err);
			break;
		}
		if (duration_sec && (time(NULL) - start) >= duration_sec)
			break;
	}

	ring_buffer__free(rb);
	container_watch_bpf__destroy(skel);
	return 0;
}
