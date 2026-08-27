# Makefile for the CO-RE libbpf program.
#
# Build steps, in order, and why each exists:
#   1. Compile container_watch.bpf.c to BPF bytecode with clang, target
#      bpf, using vmlinux.h (dumped from THIS kernel's live BTF at
#      /sys/kernel/btf/vmlinux) instead of kernel headers. This is what
#      makes the program CO-RE: field offsets get resolved at LOAD time
#      against the target kernel's own BTF, not baked in at compile time.
#   2. bpftool gen skeleton turns the compiled .o into a single C header
#      with the maps/progs already wired up, so the loader does not need
#      to hand-roll libbpf's low-level map/program lookup calls.
#   3. Compile and link the userspace loader against the skeleton and
#      libbpf.

CLANG := clang
BPFTOOL := bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

.PHONY: all clean

all: container_watch

container_watch.bpf.o: container_watch.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I. -I/usr/include/bpf \
		-c container_watch.bpf.c -o container_watch.bpf.o

container_watch.skel.h: container_watch.bpf.o
	$(BPFTOOL) gen skeleton container_watch.bpf.o > container_watch.skel.h

container_watch: container_watch.c container_watch.skel.h
	$(CLANG) -g -O2 -I. -I/usr/include/bpf \
		container_watch.c -o container_watch -lbpf -lelf -lz

clean:
	rm -f container_watch.bpf.o container_watch.skel.h container_watch
