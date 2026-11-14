# Fuzz-target build for Mercury's untrusted-byte parsers.
#
# Copyright (C) 2026 Rhizomatica
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Requires clang with libFuzzer. gcc (the tree default) cannot build these.
#   make -C tests/fuzz            # build all targets
#   make -C tests/fuzz check      # build + short smoke run over seed corpora
#
# Override the compiler if clang is not named "clang":
#   make -C tests/fuzz CC=clang-18

# clang is mandatory here regardless of the tree's default CC.
# On macOS, Apple's clang (from Command Line Tools) ships without the fuzzer
# runtime (libclang_rt.fuzzer_osx.a). The Homebrew LLVM package provides it.
# Auto-detect: prefer the Homebrew LLVM clang if the system clang lacks it.
ifeq ($(origin FUZZ_CC),undefined)
  _BREW_CLANG := /opt/homebrew/opt/llvm/bin/clang
  ifneq ($(wildcard $(_BREW_CLANG)),)
    FUZZ_CC := $(_BREW_CLANG)
  else
    FUZZ_CC := clang
  endif
endif

# Base flags mirror ../../config.mk, plus the fuzzer + sanitizers.
FUZZ_SAN     = -fsanitize=fuzzer,address,undefined
FUZZ_CFLAGS  = -Wall -O1 -g -std=gnu11 -D_GNU_SOURCE $(FUZZ_SAN) \
                -ffunction-sections
FUZZ_LDFLAGS = $(FUZZ_SAN) -lm -lpthread

PROJECT_INC = -I../../common -I../../modem -I../../datalink_arq \
              -I../../datalink_broadcast -I../../data_interfaces \
              -I../../gui_interface -I../../radio_io \
              -I../../audioio/ffaudio -I../../modem/freedv \
              -I../../gui_interface/websocket

# Populated by later tasks.
FUZZ_BINS = fuzz_arq_hdr fuzz_frame_header fuzz_kiss fuzz_arith fuzz_ws_json \
            fuzz_tnc_ctl fuzz_arq_rx fuzz_carousel fuzz_bcast_file fuzz_cfg \
            fuzz_hl2 fuzz_msg_store

# Number of iterations for the smoke `check` run (kept short: this is a
# build+no-crash gate, not a fuzzing campaign).
CHECK_RUNS ?= 20000

.PHONY: all check preflight clean print-bins
all: preflight $(FUZZ_BINS)

print-bins:
	@echo $(FUZZ_BINS)

# Fail loudly and early if the chosen compiler cannot do libFuzzer.
preflight:
	@echo 'int LLVMFuzzerTestOneInput(const unsigned char*b,unsigned long n){(void)b;(void)n;return 0;}' > .preflight.c
	@if ! $(FUZZ_CC) $(FUZZ_SAN) .preflight.c -o .preflight.bin >/dev/null 2>&1; then \
	  rm -f .preflight.c .preflight.bin; \
	  echo "ERROR: $(FUZZ_CC) cannot build -fsanitize=fuzzer targets."; \
	  echo "  On macOS: brew install llvm, then retry (auto-detected via /opt/homebrew/opt/llvm/bin/clang)."; \
	  echo "  Or pass FUZZ_CC=/path/to/clang to override."; \
	  exit 1; \
	fi
	@rm -f .preflight.c .preflight.bin
	@echo "libFuzzer preflight OK ($(FUZZ_CC))"

check: all
	@fail=0; \
	for t in $(FUZZ_BINS); do \
	  echo "--- smoke-fuzzing $$t ($(CHECK_RUNS) runs) ---"; \
	  ./$$t -runs=$(CHECK_RUNS) corpus/$$t || fail=1; \
	  if [ -n "$$(ls -A regressions/$$t 2>/dev/null | grep -v '^.gitkeep$$')" ]; then \
	    echo "--- replaying saved regressions for $$t ---"; \
	    for f in regressions/$$t/*; do \
	      [ "$$(basename $$f)" = ".gitkeep" ] && continue; \
	      ./$$t "$$f" || fail=1; \
	    done; \
	  fi; \
	done; \
	if [ $$fail -ne 0 ]; then echo "FUZZ SMOKE FAILED"; exit 1; fi; \
	printf '\n=== All fuzz smoke runs passed ===\n\n'

clean:
	rm -f $(FUZZ_BINS) .preflight.c .preflight.bin crash-* leak-* oom-* timeout-*

fuzz_arq_hdr: fuzz_arq_hdr.c ../../datalink_arq/arq_protocol.c \
              ../../datalink_arq/arith.c ../../modem/framer.c \
              ../../common/virtual_clock.c ../../common/hermes_log.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(PROJECT_INC) -o $@ $^ $(FUZZ_LDFLAGS)

fuzz_frame_header: fuzz_frame_header.c ../../modem/framer.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(PROJECT_INC) -o $@ $^ $(FUZZ_LDFLAGS)

fuzz_kiss: fuzz_kiss.c ../../datalink_broadcast/kiss.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(PROJECT_INC) -o $@ $^ $(FUZZ_LDFLAGS)

fuzz_arith: fuzz_arith.c ../../datalink_arq/arith.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(PROJECT_INC) -o $@ $^ $(FUZZ_LDFLAGS)

# Reachable by anything that can open the UI port, which is unauthenticated.
fuzz_ws_json: fuzz_ws_json.c ../../gui_interface/websocket/ws_json.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(PROJECT_INC) -o $@ $^ $(FUZZ_LDFLAGS)

# The TNC control port's command parser.  The harness #includes
# tcp_interfaces.c (its parser is static), so the .c is a prerequisite only.
fuzz_tnc_ctl: fuzz_tnc_ctl.c ../../data_interfaces/tcp_interfaces.c \
              ../../modem/framer.c ../../datalink_arq/arq_tnc.c \
              ../../common/shm_posix.c ../../common/os_interop.c \
              ../../common/mercury_modes.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(PROJECT_INC) -o $@ \
	    $(filter-out %/tcp_interfaces.c,$^) $(FUZZ_LDFLAGS)

# The ARQ receive path: FSM + carousel, on the virtual clock.
ARQ_CORE = ../datalink_arq/arq_test_stubs.c ../../datalink_arq/carousel.c \
           ../../datalink_arq/rs_erasure.c ../../datalink_arq/arq_protocol.c \
           ../../datalink_arq/arith.c ../../common/virtual_clock.c
fuzz_arq_rx: fuzz_arq_rx.c $(ARQ_CORE) ../../datalink_arq/arq_fsm.c \
             ../../datalink_arq/arq_timing.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(PROJECT_INC) -o $@ $^ $(FUZZ_LDFLAGS)

fuzz_carousel: fuzz_carousel.c $(ARQ_CORE)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(PROJECT_INC) -o $@ $^ $(FUZZ_LDFLAGS)

RAPTORQ_SRC = $(wildcard ../../datalink_broadcast/raptorq/lib/*.c) \
              $(wildcard ../../datalink_broadcast/raptorq/deps/obl/*.c)
fuzz_bcast_file: fuzz_bcast_file.c ../../datalink_broadcast/bcast_file.c $(RAPTORQ_SRC)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(PROJECT_INC) \
	    -I../../datalink_broadcast/raptorq/include -I../../datalink_broadcast/raptorq/deps \
	    -o $@ $^ $(FUZZ_LDFLAGS)

fuzz_cfg: fuzz_cfg.c ../../common/cfg_utils.c ../../radio_io/cm108_ptt.c \
          ../../common/hermes_log.c ../../common/iniparser/iniparser.c \
          ../../common/iniparser/dictionary.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(PROJECT_INC) -I../../common/iniparser -I../../audioio \
	    -o $@ $^ $(FUZZ_LDFLAGS)

# Reachable by anything on the radio's LAN segment.
fuzz_hl2: fuzz_hl2.c ../../audioio/hl2_dsp.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(PROJECT_INC) -I../../audioio -o $@ $^ $(FUZZ_LDFLAGS)

fuzz_msg_store: fuzz_msg_store.c ../../common/message_store.c ../../common/hermes_log.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(PROJECT_INC) -o $@ $^ $(FUZZ_LDFLAGS)
