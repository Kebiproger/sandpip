CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -fPIC
LDFLAGS ?= -shared -ldl

BUILD_DIR := build
SRC := src/sandpip.c
SO := $(BUILD_DIR)/sandpip.so

.PHONY: all clean test test-network

all: $(SO)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(SO): $(SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test: $(SO)
	LD_PRELOAD=$(abspath $(SO)) python3 tests/malicious.py
	LD_PRELOAD=$(abspath $(SO)) python3 tests/test_openat2.py

test-network: $(SO)
	SANDPIP_ENFORCE_NETWORK=1 SANDPIP_ALLOWED_IPS= LD_PRELOAD=$(abspath $(SO)) python3 tests/network_allowlist.py blocked
	SANDPIP_ENFORCE_NETWORK=1 SANDPIP_ALLOWED_IPS=1.1.1.1 LD_PRELOAD=$(abspath $(SO)) python3 tests/network_allowlist.py allowed
	SANDPIP_ENFORCE_NETWORK=1 LD_PRELOAD=$(abspath $(SO)) python3 tests/test_dynamic_dns.py

clean:
	rm -rf $(BUILD_DIR) sandpip.egg-info dist sandpip/sandpip.so
	find . -type d -name "__pycache__" -exec rm -rf {} +
