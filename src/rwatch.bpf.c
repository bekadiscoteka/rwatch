#include "vmlinux.h"
#include "rwatch.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {                                   // анонимная структура, имя типа не нужно
    __uint(type, BPF_MAP_TYPE_RINGBUF);    // поле "type"        = кольцевой буфер
    __uint(max_entries, 256 * 1024);       // поле "max_entries" = размер
} events                                   // переменная events — имя map'а
  SEC(".maps");

SEC("fentry/do_sys_openat2")
int BPF_PROG(handle_openat, int dfd, const char *filename, struct open_how *how)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	// TODO: без проверки на NULL verifier не загрузит программу
	if (e == NULL) 
		return 0;
	
	e->pid = bpf_get_current_pid_tgid() >> 32; 
	bpf_get_current_comm(e->comm, COMM_LEN);
	bpf_probe_read_user_str(e->path, PATH_LEN, filename);

	// TODO: pid, comm, path (filename — user-указатель)
	bpf_ringbuf_submit(e, 0);
	return 0;
}
