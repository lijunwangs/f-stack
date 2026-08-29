# M0a bench: no DPDK, no F-Stack. Builds on Linux and macOS.

TARGET = tls_bench
CFLAGS += -O2 -g -Wall -Wextra -Wno-unused-parameter

# Prefer pkg-config; fall back to a Homebrew prefix on macOS.
ifneq ($(shell pkg-config --exists openssl && echo 0),0)
  BREW_SSL := $(shell brew --prefix openssl@3 2>/dev/null)
  ifeq ($(BREW_SSL),)
    $(error "No OpenSSL found: install libssl-dev, or openssl@3 via brew")
  endif
  CFLAGS += -I$(BREW_SSL)/include
  LIBS += -L$(BREW_SSL)/lib -lssl -lcrypto
else
  CFLAGS += $(shell pkg-config --cflags openssl)
  LIBS += $(shell pkg-config --libs openssl)
endif

# The scan bench needs Hyperscan or Vectorscan; they share the libhs API and
# pkg-config name, so either satisfies this. Skipped rather than fatal when
# absent, so the TLS bench still builds on a machine without it.
HS_OK := $(shell pkg-config --exists libhs && echo yes)
ifeq ($(HS_OK),yes)
  TARGETS += scan_bench
  HS_CFLAGS := $(shell pkg-config --cflags libhs)
  HS_LIBS := $(shell pkg-config --libs libhs)
endif

all: $(TARGET) $(TARGETS)
ifneq ($(HS_OK),yes)
	@echo "note: libhs not found, skipping scan_bench (apt install libhyperscan-dev)"
endif

$(TARGET): tls_bench.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

scan_bench: scan_bench.c
	$(CC) $(CFLAGS) $(HS_CFLAGS) -o $@ $< $(HS_LIBS)

clean:
	rm -f $(TARGET) scan_bench

.PHONY: all clean
