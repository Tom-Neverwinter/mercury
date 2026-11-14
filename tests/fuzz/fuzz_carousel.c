/* libFuzzer target: the carousel data plane, driven directly.
 *
 * Copyright (C) 2026 Rhizomatica
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * One car_t, started as the callee (car_start_receiver, the slave S) or as the
 * caller (car_start_sender, the timing master M), fed what the peer would
 * send. The modem has already checked each frame's seeded CRC by the time
 * car_on_frame() sees it, so there is no CRC to get past here; the per-block
 * CRC-32 check (keyed with io.block_key) only marks the session failed after
 * the data has been delivered, so it does not stop the fuzzer either.
 *
 * Input: byte 0 = role and options, byte 1 = start rungs. Then records:
 *   0 frame   [mode] [flags] [len lo] [len hi] [len bytes]   (as fuzz_arq_rx)
 *   1 our keydown has ended (car_on_tx_done)
 *   2 pattern [kind]
 *   3 time passes [lo] [hi] ms, then car_on_time
 *   4 application data [n]: n*8 more bytes queued
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "carousel.h"
#include "freedv/freedv_api.h"
#include "modem_mfsk.h"

static const int car_modes[8] = {
    FREEDV_MODE_DATAC16, MERCURY_MODE_MFSK, FREEDV_MODE_DATAC15, FREEDV_MODE_DATAC4,
    FREEDV_MODE_DATAC3, FREEDV_MODE_DATAC1, FREEDV_MODE_DATAC17, FREEDV_MODE_QAM16C2 };

static size_t backlog;

static void io_keydown(void *ctx, const car_frame_t *f, int n)
{
    (void)ctx;
    if (n < 0 || n > CAR_KEYDOWN_MAX)
        abort();
    for (int i = 0; i < n; i++)
        if (f[i].len > CAR_FRAME_MAX)
            abort();
}
static void io_bind_rx(void *ctx, int mode) { (void)ctx; (void)mode; }
static int io_peer_keyed(void *ctx) { (void)ctx; return 0; }
static size_t io_tx_read(void *ctx, uint8_t *buf, size_t max)
{
    (void)ctx;
    size_t n = max < backlog ? max : backlog;
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(backlog - i);
    backlog -= n;
    return n;
}
static size_t io_tx_pending(void *ctx) { (void)ctx; return backlog; }
static void io_deliver(void *ctx, const uint8_t *b, size_t n)
{
    (void)ctx;
    volatile uint8_t x = 0;
    for (size_t i = 0; i < n; i++) x ^= b[i];
}
static void io_tx_confirmed(void *ctx, size_t n) { (void)ctx; (void)n; }
static void io_pattern(void *ctx, int kind) { (void)ctx; (void)kind; }
static void io_end(void *ctx) { (void)ctx; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static car_t car;   /* large: not on the stack */
    if (size < 2)
        return 0;

    uint8_t opt = data[0], lv = data[1];
    car_io_t io = {
        .keydown = io_keydown, .bind_rx = io_bind_rx, .peer_keyed = io_peer_keyed,
        .tx_read = io_tx_read, .tx_pending = io_tx_pending, .deliver = io_deliver,
        .tx_confirmed = io_tx_confirmed, .pattern = (opt & 2) ? NULL : io_pattern,
        .end = io_end, .block_key = 0x5EED1234u,
    };
    backlog = (opt & 4) ? 300 : 0;
    memset(&car, 0, sizeof(car));
    /* low nibble: the rung for the peer's direction; high: ours + 1 (0: unknown) */
    car_init(&car, &io, (lv & 15) % CAR_NLEVELS, (int)((lv >> 4) % (CAR_NLEVELS + 1)) - 1);
    car_seed_ctl_deaf(&car, (opt >> 3) & 1, (opt >> 4) & 1);
    car_seed_snr(&car, 10.0f, 10.0f);
    uint64_t now = 1000;
    if (opt & 1)
        car_start_sender(&car, now);
    else
        car_start_receiver(&car, now);

    size_t i = 2;
#define NEED(k) do { if (i + (k) > size) return 0; } while (0)
    while (i < size)
    {
        switch (data[i++] % 5)
        {
        case 0: {
            NEED(4);
            int mode = car_modes[data[i] % 8];
            uint8_t fl = data[i + 1];
            size_t n = (size_t)data[i + 2] | ((size_t)data[i + 3] << 8);
            i += 4;
            if (n > CAR_FRAME_MAX) n = CAR_FRAME_MAX;
            if (n > size - i) n = size - i;
            uint8_t *f = malloc(n ? n : 1);   /* exact size: overreads show */
            memcpy(f, data + i, n);
            i += n;
            car_on_frame(&car, now, f, n, mode, mode == FREEDV_MODE_DATAC16 || (fl & 1),
                         (float)(((fl >> 1) & 0x3f) - 10), (fl & 0x80) ? 4000 : 0);
            free(f);
            break;
        }
        case 1:
            car_on_tx_done(&car, now);
            break;
        case 2:
            NEED(1);
            car_on_pattern(&car, now, data[i++] & 1);
            break;
        case 3:
            NEED(2);
            now += (uint64_t)data[i] | ((uint64_t)data[i + 1] << 8);
            i += 2;
            car_on_time(&car, now);
            break;
        case 4:
            NEED(1);
            backlog += (size_t)data[i++] * 8;
            car_on_app_data(&car, now);
            break;
        }
    }
    return 0;
}
