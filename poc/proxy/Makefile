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

# Link order matters: libfstack needs DPDK, DPDK needs the system libs, so
# they have to appear in that order. DPDK's pkg-config emits --as-needed, so
# putting DPDK first makes the linker drop every shared object as unneeded and
# then fail on hundreds of rte_* symbols from libfstack.
LIBS += -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-whole-archive

# Static is the supported path. It drags in every transitive DPDK dependency,
# so install libjitterentropy-dev and libzstd-dev if the link complains.
#
# DPDK_SHARED=1 does NOT work against this fork as shipped: F-Stack adds
# rte_timer_meta_init to dpdk/lib/timer/ but never lists it in that library's
# version.map, so the symbol exists in the static archive and is absent from
# librte_timer.so. Using it requires adding the symbol to the version.map and
# rebuilding DPDK; -lrte_net_bond is also needed, since pkg-config --libs
# lists only the core libraries and not the drivers.
ifeq ($(DPDK_SHARED),1)
# Drop DPDK's own --as-needed, which would otherwise override ours.
comma := ,
LIBS += -Wl,--no-as-needed \
        $(filter-out -Wl$(comma)--as-needed,$(shell $(PKGCONF) --libs libdpdk)) \
        -lrte_net_bond
else
# libdpdk.pc carries OpenSSL's *static* private dependencies transitively.
# We link OpenSSL dynamically (-lcrypto -lssl below), so libcrypto.so already
# resolves those internally and they are spurious here -- notably
# -l:libjitterentropy.a, which Ubuntu does not even package. Override
# DPDK_DROP_LIBS to keep one if a link actually needs it.
DPDK_DROP_LIBS ?= -l:libjitterentropy.a
LIBS += $(filter-out $(DPDK_DROP_LIBS),$(shell $(PKGCONF) --static --libs libdpdk))
endif

LIBS += -lrt -lm -ldl -lcrypto -lssl -lz -pthread -lnuma

# libfstack.a is built without -fPIC, so a PIE link produces DT_TEXTREL.
LDFLAGS += -no-pie

TARGET = poc_proxy
SRCS = main.c session.c sni.c forge.c scan.c

all: $(TARGET)

$(TARGET): $(SRCS) proxy.h session.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS) $(LIBS)

host:
	$(MAKE) -f Makefile.host

clean:
	rm -f $(TARGET) host_test poc_ca.pem

.PHONY: all host clean
