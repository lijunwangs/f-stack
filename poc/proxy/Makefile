# POC proxy. Two builds of identical proxy logic, differing only in transport:
#
#   make                 F-Stack + DPDK (kernel bypass)
#   make STACK=kernel    kernel sockets + epoll, no DPDK needed
#
# The kernel build is the control for any comparison against a stock proxy:
# it isolates the transport from the TLS library and the application design.

TOPDIR=../..
STACK ?= fstack

ifeq ($(FF_PATH),)
	FF_PATH=${TOPDIR}
endif

PKGCONF ?= pkg-config

CFLAGS += -O2 -g -Wall -Wextra -Wno-unused-parameter -I.
COMMON_SRCS = main.c session.c sni.c forge.c scan.c

ifeq ($(STACK),kernel)

TARGET = poc_proxy_kernel
SRCS = $(COMMON_SRCS) net_kernel.c
LIBS += -lssl -lcrypto -lpthread

else ifeq ($(STACK),fstack)

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "No installation of DPDK found, maybe you should export PKG_CONFIG_PATH")
endif

TARGET = poc_proxy
SRCS = $(COMMON_SRCS) net_fstack.c

# Take the F-Stack headers from the tree, so `make install` in lib/ is not
# a prerequisite for building the POC.
CFLAGS += -I${FF_PATH}/lib
CFLAGS += $(shell $(PKGCONF) --cflags libdpdk)

# Link order matters: libfstack needs DPDK, DPDK needs the system libs, so
# they have to appear in that order. DPDK's pkg-config emits --as-needed, so
# putting DPDK first makes the linker drop every shared object as unneeded and
# then fail on hundreds of rte_* symbols from libfstack.
LIBS += -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-whole-archive

# libdpdk.pc carries OpenSSL's *static* private dependencies transitively.
# We link OpenSSL dynamically (-lcrypto -lssl below), so libcrypto.so already
# resolves those internally and they are spurious here -- notably
# -l:libjitterentropy.a, which Ubuntu does not even package. Override
# DPDK_DROP_LIBS to keep one if a link actually needs it.
DPDK_DROP_LIBS ?= -l:libjitterentropy.a
LIBS += $(filter-out $(DPDK_DROP_LIBS),$(shell $(PKGCONF) --static --libs libdpdk))
LIBS += -lrt -lm -ldl -lcrypto -lssl -lz -pthread -lnuma

# libfstack.a is built without -fPIC, so a PIE link produces DT_TEXTREL.
LDFLAGS += -no-pie

else
$(error "STACK must be fstack or kernel")
endif

all: $(TARGET)

$(TARGET): $(SRCS) proxy.h session.h net.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS) $(LIBS)

# Both builds, for a like-for-like comparison.
both:
	$(MAKE) STACK=fstack
	$(MAKE) STACK=kernel

host:
	$(MAKE) -f Makefile.host

clean:
	rm -f poc_proxy poc_proxy_kernel host_test poc_ca.pem

.PHONY: all both host clean
