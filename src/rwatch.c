#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "rwatch.skel.h"
#include "rwatch.h"

static int handle_event(void *ctx, void *data, size_t size);  // вернуть 0 = продолжать

volatile sig_atomic_t stop = 0;

void  handle_sigint(int sig) {
	(void)sig;
	const char msg[] = "\n[SIGNAL] Получен сигнал прерывания. Завершаем работу...\n";
	if (write(STDERR_FILENO, msg, sizeof(msg) - 1) == -1)
		exit(1);
	stop = 1;
}

int main(void)
{
	printf("SCANNING FOR: openat2 rename\n");


	struct sigaction sa;
	sa.sa_handler = handle_sigint;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) < 0) {
		perror("sigaction SIGINT");
		return 1;
	}
	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		perror("sigaction SIGTERM");
		return 1;
	}

	struct rwatch_bpf *skel = rwatch_bpf__open_and_load();
	if (skel == NULL) 
		return 1;

	if (rwatch_bpf__attach(skel) != 0) {
		rwatch_bpf__destroy(skel);
		return 1;
	}

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (rb == NULL) { 
		ring_buffer__free(rb); 
		rwatch_bpf__destroy(skel);
		return 1;
	}
		

	while (!stop) 
		ring_buffer__poll(rb, 100 /* мс */);


	ring_buffer__free(rb); 
	rwatch_bpf__destroy(skel);

	return 0;

}


static int handle_event(void *cctx,  void  *data, size_t size) {
	(void)cctx;
	(void)size;
	struct event *e = (struct event *) data;		

	switch (e->type) {
		case RW_OPEN:
			printf("\tProcess ID: %d\ttype: %s\tName: %s\tPath: %s\tflags: %llx\n", 
				e->pid, "open/write",  e->comm, e->path, e->flags);
			break;
		case RW_RENAME:
			printf("\tProcess ID: %d\tName: %s\ttype: %s\told path: %s\tpath: %s\tflags: %llx\n", 
				e->pid, e->comm, "rename", e->oldpath, e->path, e->flags);
			break;
		default:
			printf("Unsupported type\n");
			break;

	}

	return 0;
}







