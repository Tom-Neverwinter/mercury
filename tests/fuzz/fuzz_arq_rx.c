/* libFuzzer target: the ARQ receive path, FSM and carousel data plane.
 *
 * Copyright (C) 2026 Rhizomatica
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * What arq.c does with a decoded frame -- CALL/ACCEPT through the protocol
 * parsers, a plain DISCONNECT through the header decoder, a seeded session
 * frame straight to the FSM as ARQ_EV_RX_CAROUSEL (and from there to
 * car_on_frame) -- driven single-threaded, on the virtual clock, with the
 * modem and the TNC stubbed.
 *
 * Input: byte 0 picks the start: a scripted handshake to CONNECTED as caller
 * or as callee, ACCEPTING (callee, ACCEPT sent), or bare LISTENING. The rest
 * is a list of records, [op] [args...]:
 *   0 RX_CAROUSEL  [mode] [flags] [len lo] [len hi] [len bytes]
 *                  flags: bit 0 control decoder, bits 1-6 SNR+10 dB, bit 7 late
 *   1 CALL frame   [len] [bytes]  -> arq_protocol_parse_call, as arq.c
 *   2 ACCEPT frame [len] [bytes]  -> arq_protocol_parse_accept, as arq.c
 *   3 plain frame  [len] [bytes]  -> header decode; DISCONNECT -> RX_DISCONNECT
 *   4 TX_COMPLETE (and TX_STARTED when the flag byte's bit 0 is set) [flag]
 *   5 RX_PATTERN   [break]
 *   6 time passes  [lo] [hi]      ms; a due deadline fires, as the event loop
 *   7 app          [kind] [n]     LISTEN, DATA_READY with n*16 more bytes,
 *                                 DISCONNECT, ABORT, LISTEN OFF, CONNECT K1ABC
 * The connect frames are not checked against our callsign's CRC (arq.c does),
 * so the fuzzer need not find it.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

#include "arq.h"
#include "arq_fsm.h"
#include "carousel.h"
#include "framer.h"
#include "modem_mfsk.h"
#include "arq_protocol.h"
#include "arq_timing.h"
#include "virtual_clock.h"
#include "freedv/freedv_api.h"

static arq_session_t sess;

/* ---- the callbacks arq.c would give the FSM ---- */
static size_t backlog;   /* application bytes waiting to go */

static void cb_send_tx_frame(int pt, int mode, size_t n, const uint8_t *f, int more)
{ (void)pt; (void)mode; (void)n; (void)f; (void)more; }
static void cb_notify_connected(const char *r, const char *l, bool we)
{ (void)r; (void)l; (void)we; }
static void cb_notify_pending(const char *r, const char *l) { (void)r; (void)l; }
static void cb_notify_pending_again(const char *r) { (void)r; }
static void cb_notify_cancelpending(void) { }
static void cb_notify_disconnected(bool all) { (void)all; }
static void cb_deliver_rx_data(const uint8_t *d, size_t n)
{
    /* Touch every byte so ASan sees a bad pointer/length. */
    volatile uint8_t x = 0;
    for (size_t i = 0; i < n; i++) x ^= d[i];
    if (getenv("FUZZ_VERBOSE"))
        fprintf(stderr, "delivered %zu bytes in %s\n", n, arq_conn_state_name(sess.conn_state));
}
static int cb_tx_backlog(void) { return (int)backlog; }
static int cb_tx_read(uint8_t *buf, size_t len)
{
    size_t n = len < backlog ? len : backlog;
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(backlog - i);
    backlog -= n;
    return (int)n;
}
static void cb_send_buffer_status(int b) { (void)b; }
static void cb_send_keydown(const arq_keydown_t *kd) { (void)kd; }
static void cb_send_pattern(int kind) { (void)kind; }
static void cb_set_crc_seed(uint16_t seed) { (void)seed; }
static void cb_set_floor_mode(int mode) { (void)mode; }

static const arq_fsm_callbacks_t cbs = {
    .send_tx_frame        = cb_send_tx_frame,
    .notify_connected     = cb_notify_connected,
    .notify_pending       = cb_notify_pending,
    .notify_pending_again = cb_notify_pending_again,
    .notify_cancelpending = cb_notify_cancelpending,
    .notify_disconnected  = cb_notify_disconnected,
    .deliver_rx_data      = cb_deliver_rx_data,
    .tx_backlog           = cb_tx_backlog,
    .tx_read              = cb_tx_read,
    .send_buffer_status   = cb_send_buffer_status,
    .send_keydown         = cb_send_keydown,
    .send_pattern         = cb_send_pattern,
    .set_crc_seed         = cb_set_crc_seed,
    .set_floor_mode       = cb_set_floor_mode,
};

/* The modes a session frame comes on: the control mode and the ladder. Same
 * table, same record layout as fuzz_carousel, so seeds carry over. */
static const int car_modes[8] = {
    FREEDV_MODE_DATAC16, MERCURY_MODE_MFSK, FREEDV_MODE_DATAC15, FREEDV_MODE_DATAC4,
    FREEDV_MODE_DATAC3, FREEDV_MODE_DATAC1, FREEDV_MODE_DATAC17, FREEDV_MODE_QAM16C2 };

static arq_timing_ctx_t timing;
static uint64_t now_ms;

static void dispatch(arq_event_t *ev) { arq_fsm_dispatch(&sess, ev); }

static void simple(arq_event_id_t id)
{
    arq_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.id = id;
    dispatch(&ev);
}

static void fire_deadline(void)
{
    if (sess.deadline_ms != UINT64_MAX && now_ms >= sess.deadline_ms)
    {
        sess.deadline_ms = UINT64_MAX;
        simple(sess.deadline_event);
    }
}

/* arq_handle_incoming_connect_frame, less the callsign-CRC match. */
static void connect_frame(const uint8_t *d, size_t n, bool accept_op)
{
    if (n < 2)
        return;
    arq_event_t ev;
    memset(&ev, 0, sizeof(ev));
    if (!arq_protocol_connect_version_ok(d, n))
        return;
    if (accept_op)
    {
        arq_accept_t acc;
        if (arq_protocol_parse_accept(d, n, &acc) != 0)
            return;
        ev.id = ARQ_EV_RX_ACCEPT;
        ev.session_id     = acc.session_id;
        ev.bw_hz          = acc.bw_hz;
        ev.tx_mfsk        = acc.tx_mfsk;
        ev.car_level      = acc.start_level;
        ev.car_ctl_deaf   = acc.ctl_deaf;
        ev.car_call_snr   = isnan(acc.call_snr_db) ? 0.0f : acc.call_snr_db;
        ev.car_nonce      = acc.nonce;
        ev.car_called_crc = acc.called_crc;
    }
    else
    {
        char caller[CALLSIGN_MAX_SIZE] = {0};
        if (arq_protocol_parse_call(d, n, &ev.session_id, caller, &ev.bw_hz, &ev.tx_mfsk) != 0)
            return;
        if (!memchr(caller, 0, sizeof(caller)))
            abort();
        ev.id = ARQ_EV_RX_CALL;
        snprintf(ev.remote_call, sizeof(ev.remote_call), "%s", caller);
    }
    snprintf(ev.local_call, sizeof(ev.local_call), "%s", "N0CALL");
    dispatch(&ev);
}

static void start(uint8_t how)
{
    arq_event_t ev;
    /* The SNR the connect frame was read at: it picks the start rungs. */
    float snr = (float)((how >> 2) % 32) - 5.0f;
    simple(ARQ_EV_APP_LISTEN);
    switch (how % 4)
    {
    case 0:   /* callee, connected on the caller's first frame */
    case 1:   /* callee, ACCEPT sent and waiting */
        memset(&ev, 0, sizeof(ev));
        ev.id = ARQ_EV_RX_CALL;
        ev.session_id = 0x43;
        ev.bw_hz = 2300;
        ev.rx_snr = snr;
        snprintf(ev.remote_call, sizeof(ev.remote_call), "K1ABC");
        snprintf(ev.local_call, sizeof(ev.local_call), "N0CALL");
        dispatch(&ev);
        simple(ARQ_EV_TIMER_RETRY);   /* the ACCEPT goes out, the seed is set */
        simple(ARQ_EV_TX_COMPLETE);
        if (how % 4 == 0)
        {
            memset(&ev, 0, sizeof(ev));
            ev.id = ARQ_EV_RX_CAROUSEL;
            ev.session_id = 0x43;
            ev.mode = FREEDV_MODE_DATAC15;
            dispatch(&ev);
        }
        break;
    case 2:   /* caller, connected on the ACCEPT */
        memset(&ev, 0, sizeof(ev));
        ev.id = ARQ_EV_APP_CONNECT;
        snprintf(ev.remote_call, sizeof(ev.remote_call), "K1ABC");
        dispatch(&ev);
        memset(&ev, 0, sizeof(ev));
        ev.id = ARQ_EV_RX_ACCEPT;
        ev.session_id = sess.session_id;
        ev.bw_hz = 2300;
        ev.rx_snr = snr;
        ev.car_call_snr = snr;
        ev.car_level = car_start_level(snr);
        ev.car_called_crc = arq_protocol_callsign_crc16("K1ABC");
        snprintf(ev.remote_call, sizeof(ev.remote_call), "K1ABC");
        dispatch(&ev);
        simple(ARQ_EV_TX_COMPLETE);
        break;
    default:  /* listening: the fuzz input has to make the call itself */
        break;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;

    now_ms = 100000;
    virtual_clock_enable(now_ms);
    memset(&arq_conn, 0, sizeof(arq_conn));
    snprintf(arq_conn.my_call_sign, sizeof(arq_conn.my_call_sign), "N0CALL");
    arq_conn.bw = 2300;
    backlog = 0;
    arq_timing_init(&timing);
    arq_fsm_set_timing(&timing);
    arq_fsm_set_callbacks(&cbs);
    arq_fsm_init(&sess);

    start(data[0]);

    size_t i = 1;
#define NEED(k) do { if (i + (k) > size) goto out; } while (0)
    while (i < size)
    {
        uint8_t op = data[i++] % 8;
        arq_event_t ev;
        memset(&ev, 0, sizeof(ev));
        switch (op)
        {
        case 0: {
            NEED(4);
            ev.id = ARQ_EV_RX_CAROUSEL;
            ev.session_id = sess.session_id;
            ev.mode = car_modes[data[i] % 8];
            ev.from_control = data[i + 1] & 1;
            ev.rx_snr = (float)(((data[i + 1] >> 1) & 0x3f) - 10);
            ev.rx_age_ms = (uint32_t)(data[i + 1] & 0x80 ? 4000 : 0);
            size_t n = (size_t)data[i + 2] | ((size_t)data[i + 3] << 8);
            i += 4;
            if (n > sizeof(ev.payload)) n = sizeof(ev.payload);
            if (n > size - i) n = size - i;
            memcpy(ev.payload, data + i, n);
            ev.payload_len = n;
            i += n;
            dispatch(&ev);
            break;
        }
        case 1:
        case 2:
        case 3: {
            NEED(1);
            size_t n = data[i++] % 32;
            if (n > size - i) n = size - i;
            uint8_t buf[32];
            memcpy(buf, data + i, n);   /* exact-size copy: overreads show */
            i += n;
            if (op == 3)
            {
                arq_frame_hdr_t hdr;
                if (n >= ARQ_FRAME_HDR_SIZE && arq_protocol_decode_hdr(buf, n, &hdr) == 0 &&
                    hdr.packet_type == PACKET_TYPE_ARQ_CONTROL &&
                    hdr.subtype == ARQ_SUBTYPE_DISCONNECT)
                {
                    ev.id = ARQ_EV_RX_DISCONNECT;
                    ev.session_id = hdr.session_id;
                    dispatch(&ev);
                }
            }
            else
                connect_frame(buf, n, op == 2);
            break;
        }
        case 4:
            NEED(1);
            if (data[i++] & 1)
                simple(ARQ_EV_TX_STARTED);
            simple(ARQ_EV_TX_COMPLETE);
            break;
        case 5:
            NEED(1);
            ev.id = ARQ_EV_RX_PATTERN;
            ev.pattern_break = data[i++] & 1;
            dispatch(&ev);
            break;
        case 6:
            NEED(2);
            now_ms += (uint64_t)data[i] | ((uint64_t)data[i + 1] << 8);
            i += 2;
            virtual_clock_set(now_ms);
            fire_deadline();
            break;
        case 7:
            NEED(2);
            switch (data[i] % 6)
            {
            case 0: ev.id = ARQ_EV_APP_LISTEN; break;
            case 1: backlog += (size_t)data[i + 1] * 16; ev.id = ARQ_EV_APP_DATA_READY; break;
            case 2: ev.id = ARQ_EV_APP_DISCONNECT; break;
            case 3: ev.id = ARQ_EV_APP_DISCONNECT; ev.abort = true; break;
            case 4: ev.id = ARQ_EV_APP_STOP_LISTEN; break;
            default:
                ev.id = ARQ_EV_APP_CONNECT;
                snprintf(ev.remote_call, sizeof(ev.remote_call), "K1ABC");
                break;
            }
            i += 2;
            dispatch(&ev);
            break;
        }
    }
out:
    arq_fsm_release(&sess);
    return 0;
}
