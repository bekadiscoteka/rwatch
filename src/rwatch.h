#ifndef RWATCH_H
#define RWATCH_H
#define PATH_LEN 256
#define COMM_LEN 16


struct event {
    // TODO: pid, comm, path, позже type и flags
    pid_t pid;
    char comm[COMM_LEN];
    char path[PATH_LEN];
};
#endif



