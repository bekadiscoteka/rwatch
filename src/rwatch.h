#ifndef RWATCH_H
#define RWATCH_H
#define PATH_LEN 256
#define COMM_LEN 16

enum types { RW_OPEN=1, RW_RENAME, RW_UNLINK};

struct event {
    pid_t pid;
    char comm[COMM_LEN];
    char oldpath[PATH_LEN]; // for rename type only
    char path[PATH_LEN];
    __u64 flags;
    enum types type;
};
#endif



