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

CFLAGS := -O3 -g -target bpf -mcpu=probe -fno-stack-protector \
          -Wall -Wno-unused-value \
          -I. -I/usr/include -I$(ASM_INC) -I/usr/include/bpf \
          $(ARCH_FLAGS)

SRCS := $(wildcard *_handler.c)
OBJS := $(SRCS:.c=.o)

.PHONY: all clean

all: $(OBJS)

%.o: %.c xdp_slot_ctx.h
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)