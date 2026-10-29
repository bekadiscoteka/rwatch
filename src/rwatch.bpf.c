#include "vmlinux.h"
#include "rwatch.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define O_RDONLY	0
#define O_ACCMODE  	00000003
#define O_TRUNC    	00001000
#define O_APPEND   	00002000

char LICENSE[] SEC("license") = "GPL";

struct {                                   
    __uint(type, BPF_MAP_TYPE_RINGBUF);   
    __uint(max_entries, 256 * 1024);     
} events                                
  SEC(".maps");

static __always_inline bool isdanger(__u64 f) {
	if ((f & O_TRUNC) == O_TRUNC) 
		return true;
	else if ( (f & O_APPEND) == O_APPEND) 
		return true;
	else if ((f & O_ACCMODE) != O_RDONLY) 
		return true;
	return false;
}


SEC("fentry/do_sys_openat2")
int BPF_PROG(handle_openat, int dfd, const char *filename, struct open_how *how)
{
	if (isdanger(how->flags) == false)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e == NULL) 
		return 0;
	
	e->pid = bpf_get_current_pid_tgid() >> 32; 
	bpf_get_current_comm(e->comm, COMM_LEN);
	bpf_probe_read_user_str(e->path, PATH_LEN, filename);
	e->flags = how->flags;
	e->type = RW_OPEN;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/filename_renameat2")
int BPF_PROG(handle_rename, int olddfd, struct filename *from,
             int newdfd, struct filename *to, unsigned int flags)
{

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e == NULL) 
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32; 
	bpf_get_current_comm(e->comm, COMM_LEN);
	e->flags = flags;
	e->type = RW_RENAME;

	bpf_probe_read_kernel_str(e->oldpath, PATH_LEN, from->name);
	bpf_probe_read_kernel_str(e->path, PATH_LEN, to->name);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/filename_unlinkat")
int BPF_PROG(handle_unlink, int dfd, struct filename *fname) {
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); 
	if (e == NULL)
		return 0;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(e->comm, COMM_LEN);
	e->flags = 0;
	e->type = RW_UNLINK;

	bpf_probe_read_kernel_str(e->path, PATH_LEN, fname->name);

	bpf_ringbuf_submit(e, 0);
	return 0;
}


