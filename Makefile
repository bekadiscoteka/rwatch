# rwatch — сборка eBPF-части и user-space загрузчика
#
#   make            — собрать всё, что уже есть (bpf.o, skel.h, rwatch если есть rwatch.c)
#   make bpf        — только src/rwatch.bpf.o
#   make load       — этап 1: загрузить через bpftool (autoattach), без своего лоадера
#   make unload     — выгрузить то, что загрузил make load
#   make trace      — читать bpf_printk из trace_pipe
#   make clean

CLANG   ?= clang
CC      ?= gcc
BPFTOOL ?= bpftool

SRC := src
ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

BPF_CFLAGS := -O2 -g -Wall -Wno-missing-declarations -fms-extensions -Wno-microsoft-anon-tag -target bpf -D__TARGET_ARCH_$(ARCH) -I$(SRC)
CFLAGS     := -O2 -g -Wall -Wextra -I$(SRC)
LDLIBS     := -lbpf -lelf -lz

BPF_OBJ  := $(SRC)/rwatch.bpf.o
SKEL     := $(SRC)/rwatch.skel.h
VMLINUX  := $(SRC)/vmlinux.h
PIN_DIR  := /sys/fs/bpf/rwatch

# user-space бинарь собираем, только когда появится src/rwatch.c (этап 2)
TARGETS := $(BPF_OBJ) $(SKEL)
ifneq ($(wildcard $(SRC)/rwatch.c),)
TARGETS += rwatch
endif

.PHONY: all bpf load unload trace clean

all: $(TARGETS)

bpf: $(BPF_OBJ)

# Типы ядра из BTF — генерируем один раз
$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Ядерная часть: C -> BPF-байткод (+ BTF благодаря -g)
$(BPF_OBJ): $(SRC)/rwatch.bpf.c $(VMLINUX) $(wildcard $(SRC)/rwatch.h)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Скелетон: .o, вшитый в заголовок + функции open/load/attach/destroy
$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# User space
rwatch: $(SRC)/rwatch.c $(SKEL) $(wildcard $(SRC)/rwatch.h)
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

load: $(BPF_OBJ)
	sudo $(BPFTOOL) prog loadall $< $(PIN_DIR) autoattach

unload:
	sudo rm -rf $(PIN_DIR)

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm -f $(SRC)/*.o $(SRC)/*.skel.h rwatch
