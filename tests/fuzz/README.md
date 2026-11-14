# Fuzzing Mercury's byte-input parsers

These libFuzzer targets exercise the parsers that consume untrusted bytes off the
air, off the TCP/KISS link, or from the WebSocket UI. They are **opt-in**: they are
not part of the blocking CI gates and require clang with libFuzzer.

## Targets

| Target | Parses |
| --- | --- |
| `fuzz_arq_hdr` | ARQ frame headers off the air |
| `fuzz_frame_header` | modem framer headers |
| `fuzz_kiss` | KISS frames off the TCP link |
| `fuzz_arith` | the arithmetic coder |
| `fuzz_ws_json` | UI commands off the WebSocket port (unauthenticated) |
| `fuzz_tnc_ctl` | TNC control-port command lines (`process_control_bytes`), split across reads |
| `fuzz_arq_rx` | the ARQ receive path: CALL/ACCEPT parsers, DISCONNECT, session frames through the FSM into the carousel, in every connection state |
| `fuzz_carousel` | the carousel data plane (`car_on_frame` and its timers) as caller or callee |
| `fuzz_bcast_file` | broadcast file frames (RaptorQ); checks nothing is written outside the download dir |
| `fuzz_cfg` | the INI config (`cfg_read`/`cfg_write`); `FUZZ_CFG_ROUNDTRIP=1` also asserts the round trip |
| `fuzz_hl2` | Hermes Lite 2 UDP discovery replies and EP6 packets, on into the RX DSP |
| `fuzz_msg_store` | the persisted message store (JSONL) load, trim and rewrite |

`fuzz_arq_hdr` and `fuzz_frame_header` are shallow (a length check and a byte
or two); `fuzz_arq_rx` is the one that reaches what a received frame does.

## Build

    make -C tests/fuzz            # build all targets (needs clang)
    make -C tests/fuzz CC=clang-18  # if your clang is named differently

## Smoke test (build + short no-crash run over the seed corpus)

    make -C tests/fuzz check

This is what a reviewer runs to confirm the targets build and survive their seeds.
It is a gate on *no crash*, not a real campaign.

## Real fuzzing run

    cd tests/fuzz
    ./fuzz_kiss corpus/fuzz_kiss            # runs until a crash or Ctrl-C
    ./fuzz_kiss -max_total_time=300 corpus/fuzz_kiss   # 5-minute campaign

libFuzzer writes new interesting inputs into the corpus dir and, on a finding,
drops a `crash-<sha1>` / `leak-<sha1>` file in the current directory.

## Triage a finding

1. Copy the reproducer into the regression corpus so it is replayed forever:
   `cp crash-<sha1> regressions/fuzz_kiss/`
2. Re-run just that input to confirm and to get the sanitizer stack:
   `./fuzz_kiss regressions/fuzz_kiss/crash-<sha1>`
3. Fix the parser, then confirm the reproducer now passes:
   `./fuzz_kiss regressions/fuzz_kiss/crash-<sha1>` exits 0.

`make check` replays every file under `regressions/<target>/` too (they live
alongside the seed corpus), so a fixed bug cannot silently regress.

## Roadmap / future work

- **OSS-Fuzz onboarding**: these targets follow the standard libFuzzer entry-point
  shape (`LLVMFuzzerTestOneInput`), so an OSS-Fuzz `project.yaml` + `build.sh` that
  compiles `tests/fuzz/*.c` would give continuous cloud fuzzing for free. Good
  candidate given Mercury is open-source humanitarian comms infrastructure.
- **CI job**: a non-blocking scheduled workflow could run `make -C tests/fuzz check`
  (build + short smoke) on a timer. Deliberately not added in this PR to keep the
  blocking gates fast and gcc-only.
