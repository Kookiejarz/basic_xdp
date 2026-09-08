CLANG ?= clang
ARCH  := $(shell uname -m)

ifeq ($(ARCH),x86_64)
    ASM_INC    := /usr/include/x86_64-linux-gnu
    ARCH_FLAGS := -D__TARGET_ARCH_x86 -D__x86_64__
else ifneq (,$(filter $(ARCH),aarch64 arm64))
    ASM_INC    := /usr/include/aarch64-linux-gnu
    ARCH_FLAGS := -D__TARGET_ARCH_arm64 -D__aarch64__
else
    ASM_INC    := /usr/include
    ARCH_FLAGS :=
endif

CFLAGS := -O3 -g -target bpf -mcpu=v3 -fno-stack-protector \
          -Wall -Wno-unused-value \
           -I. -I../bpf/include -I/usr/include -I$(ASM_INC) -I/usr/include/bpf \
          $(ARCH_FLAGS)

SRCS := $(wildcard *_handler.c)
OBJS := $(SRCS:.c=.o)

.PHONY: all clean

all: $(OBJS)

%.o: %.c xdp_slot_ctx.h xdp_profile_ctx.h ../bpf/include/map_sizes.h
	$(CLANG) $(CFLAGS) -c $< -o $@

minecraft_handler.o: ../bpf/include/counters.h ../bpf/include/flow_keys.h

clean:
	rm -f $(OBJS)
