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

all: $(TARGET)

$(TARGET): tls_bench.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
