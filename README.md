# rwatch

A small eBPF tool that watches file activity of processes on Linux,
aimed at catching ransomware-like behaviour: opening many files for writing,
truncating them, renaming them to `.locked`.

Written in C with libbpf and CO-RE. The kernel part is loaded through a
`bpftool`-generated skeleton; events go to user space through a BPF ring buffer.

## Status

- [x] `openat` / `open` / `creat`: only opens for writing (`O_WRONLY`, `O_RDWR`, `O_TRUNC`), filtered in the kernel
- [x] `rename` / `renameat` / `renameat2`: old and new path
- [ ] `unlinkat`
- [ ] ignore rwatch's own pid
- [ ] detector: per-pid sliding window, alert on threshold, optional `--kill`
- [ ] demo with a fake ransomware script

## Architecture

```
 kernel                                        user space (rwatch)
 ──────                                        ───────────────────
 fentry/do_sys_openat2      ─┐
   filter: write opens only  ├─► BPF ring buffer ──mmap──► ring_buffer__poll()
 fentry/filename_renameat2  ─┘   (struct event)              └─ handle_event(): switch on e->type
```

`src/rwatch.h` holds `struct event`, shared by both sides. Each event carries
`type`, `pid`, `comm`, `path` (the file's name after the event), `oldpath`
(rename only) and `flags`.

### Why fentry and not syscall tracepoints

The first version used `tracepoint/syscalls/sys_enter_openat`. On kernel
7.0.0 (Ubuntu, VirtualBox) it silently missed whole processes: for one
`cat /etc/hostname`, `raw_syscalls:sys_enter` (id 257), a kprobe and an fentry
on `do_sys_openat2` each saw 4 calls, the tracepoint saw 0. I did not find
the root cause.

The hooks now sit on the internal functions where all variants of the
syscall end up:

| syscalls | hook | path argument |
|---|---|---|
| `open`, `openat`, `openat2`, `creat` | `fentry/do_sys_openat2` | user memory → `bpf_probe_read_user_str` |
| `rename`, `renameat`, `renameat2` | `fentry/filename_renameat2` | already copied into `struct filename` → `bpf_probe_read_kernel_str` |

The cost: these are internal kernel functions, not a stable ABI.
`filename_renameat2` was called `do_renameat2` in older kernels.

## Build

Requirements: kernel 5.8+ with BTF (`/sys/kernel/btf/vmlinux`), clang, libbpf, bpftool.

```bash
sudo apt install clang llvm libbpf-dev libelf-dev zlib1g-dev make \
                 linux-tools-common linux-tools-$(uname -r)
make
```

`make` generates `src/vmlinux.h` from the running kernel's BTF, compiles the
BPF object, generates the skeleton and builds `./rwatch`.

Tested on: Ubuntu, kernel 7.0.0-38-generic, clang 18.1.3, bpftool 7.7, libbpf 1.3.

## Run

```bash
sudo ./rwatch
```

In another terminal:

```bash
echo hi > /tmp/a.txt                 # open for write: shown
cat /tmp/a.txt                       # read-only open: filtered out
mv /tmp/a.txt /tmp/a.txt.locked      # rename: shown
```

<!-- TODO: paste real output here -->

## Limitations

- Paths are reported exactly as the process passed them: relative paths
  (`cd /tmp && mv a b`) come without the directory.
- Paths longer than 255 bytes are truncated.
- Opening for write is not the same as writing: `write()` itself is not traced yet.
- If user space falls behind and the ring buffer fills up, new events are dropped.
- Hooks depend on internal kernel function names and may need changes on other kernels.
