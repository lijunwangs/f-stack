# POC proxy: needs DPDK + libfstack, so this builds on Linux only.
# For the parts that build anywhere, see Makefile.host.

TOPDIR=../..

ifeq ($(FF_PATH),)
	FF_PATH=${TOPDIR}
endif

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "No installation of DPDK found, maybe you should export PKG_CONFIG_PATH")
endif

PKGCONF ?= pkg-config

CFLAGS += -O2 -g -Wall -Wextra -Wno-unused-parameter -I.
# Take the F-Stack headers from the tree, so `make install` in lib/ is not
# a prerequisite for building the POC.
CFLAGS += -I${FF_PATH}/lib
CFLAGS += $(shell $(PKGCONF) --cflags libdpdk)

# Static by default, matching the in-tree examples. Static linking drags in
# every transitive DPDK dependency (libjitterentropy, libzstd, ...), so if
# those are missing and cannot be installed, build with DPDK_SHARED=1 to link
# DPDK dynamically instead -- the shared objects record their own deps.
ifeq ($(DPDK_SHARED),1)
LIBS += $(shell $(PKGCONF) --libs libdpdk)
else
LIBS += $(shell $(PKGCONF) --static --libs libdpdk)
endif
LIBS += -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-whole-archive
LIBS += -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -lssl -lz -pthread -lnuma

TARGET = poc_proxy
SRCS = main.c session.c sni.c forge.c scan.c

all: $(TARGET)

$(TARGET): $(SRCS) proxy.h session.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LIBS)

host:
	$(MAKE) -f Makefile.host

clean:
	rm -f $(TARGET) host_test poc_ca.pem

.PHONY: all host clean
