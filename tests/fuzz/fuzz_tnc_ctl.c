/* libFuzzer target: VARA-style TNC control-command parser.
 *
 * Copyright (C) 2026 Rhizomatica
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Feeds bytes through process_control_bytes() of data_interfaces/tcp_interfaces.c,
 * which accumulates '\r'-terminated lines and runs execute_control_command() on
 * each. Both are static, so (like tests/data_interfaces/test_tcp_interfaces.c)
 * we #include the .c and stub what it calls. The first input byte drives where
 * the rest is split across calls, so partial-line state across reads is
 * exercised too. Every command handed to the ARQ layer must carry NUL-terminated
 * argument strings.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <sys/types.h>

#include "os_interop.h"
#include "ring_buffer_posix.h"
#include "net.h"
#include "arq.h"
#include "defines_modem.h"
#include "kiss.h"
#include "hermes_log.h"
#include "radio_io.h"

/* Control-line queue: swallowed, not put in a ring. */
static int swallow_line(const uint8_t *line, size_t len)
{
    (void)line; (void)len;
    return 0;
}
#define TNC_TXQ_PUT(q, data, len) swallow_line((data), (len))
#include "../../data_interfaces/tcp_interfaces.c"

/* ---- hermes_log ---- */
void hermes_logf(hermes_log_level_t level, const char *component, const char *fmt, ...)
{ (void)level; (void)component; (void)fmt; }
uint64_t hermes_uptime_ms(void) { return 1000; }

/* ---- arq ---- */
static void must_be_terminated(const char *s, size_t cap)
{
    if (!memchr(s, '\0', cap))
        abort();
}

int arq_submit_tcp_cmd(const arq_cmd_msg_t *cmd)
{
    must_be_terminated(cmd->arg0, sizeof(cmd->arg0));
    must_be_terminated(cmd->arg1, sizeof(cmd->arg1));
    return 0;
}
int arq_submit_tcp_payload(const uint8_t *data, size_t len) { (void)data; (void)len; return 0; }
bool arq_get_runtime_snapshot(arq_runtime_snapshot_t *s) { memset(s, 0, sizeof(*s)); return true; }
int arq_reported_bandwidth_hz(void) { return 2300; }
bool arq_is_link_connected(void) { return false; }
void arq_discard_stale_rx(void) { }
void arq_set_trx(int trx) { arq_conn.TRX = trx; }
int  arq_get_trx(void)    { return arq_conn.TRX; }
void arq_conn_get_calls(char *my_call, char *src_addr, char *dst_addr, size_t bufsz)
{
    if (bufsz == 0) return;
    if (my_call)  snprintf(my_call,  bufsz, "%s", arq_conn.my_call_sign);
    if (src_addr) snprintf(src_addr, bufsz, "%s", arq_conn.src_addr);
    if (dst_addr) snprintf(dst_addr, bufsz, "%s", arq_conn.dst_addr);
}

/* ---- message_store ---- */
void msg_store_feed(const char *plane, const char *dir, const char *peer,
                    const uint8_t *data, size_t len)
{ (void)plane; (void)dir; (void)peer; (void)data; (void)len; }
void msg_store_reset(const char *plane, const char *dir) { (void)plane; (void)dir; }

/* ---- net ---- */
int cli_ctl_sockfd = -1;
int cli_data_sockfd = -1;
atomic_int status_ctl = 0;
atomic_int status_data = 0;
ssize_t tcp_write(int pt, uint8_t *b, size_t n) { (void)pt; (void)b; return (ssize_t)n; }
ssize_t tcp_write_all(int pt, uint8_t *b, size_t n) { (void)pt; (void)b; return (ssize_t)n; }
void net_set_status(int pt, int st) { (void)pt; (void)st; }
int net_get_status(int pt) { (void)pt; return NET_CONNECTED; }
ssize_t tcp_send_some(int pt, const uint8_t *b, size_t n) { (void)pt; (void)b; return (ssize_t)n; }
int net_wait_for_status(int p, int s, int t) { (void)p; (void)s; (void)t; return 0; }
int net_wait_while_status(int p, int s, int t) { (void)p; (void)s; (void)t; return 0; }
int listen4connection(int p) { (void)p; return 0; }
ssize_t tcp_read(int pt, uint8_t *b, size_t s) { (void)pt; (void)b; (void)s; return 0; }
int tcp_close(int pt) { (void)pt; return 0; }

/* ---- radio_io ---- */
bool radio_io_enabled(void) { return false; }
int radio_io_key_on(void) { return 0; }
int radio_io_key_off(void) { return 0; }

/* ---- modem ---- */
int   modem_tune_start(float dbfs) { (void)dbfs; return 0; }
void  modem_tune_stop(void) { }
bool  modem_tune_active(void) { return false; }
float modem_tune_level_dbfs(void) { return -15.0f; }
int    modem_set_listen_mode(int mode) { (void)mode; return 0; }
int    modem_get_listen_mode(void) { return FREEDV_MODE_DATAC15; }
size_t modem_get_broadcast_frame_size(void) { return 14; }
bool modem_beacon_mode_ok(int mode) { return mode == FREEDV_MODE_DATAC16 || mode == FREEDV_MODE_DATAC15; }
int  modem_beacon_send(const uint8_t *f, size_t n, int mode) { (void)f; (void)n; (void)mode; return 0; }
static bool monitor_on;
void modem_set_monitor_enabled(bool e) { monitor_on = e; }
bool modem_get_monitor_enabled(void) { return monitor_on; }
void modem_busy_channel_changed(void) { }
static bool busy_detect, busy_reseed;
void modem_set_busy_detect_enabled(bool e) { busy_detect = e; }
bool modem_get_busy_detect_enabled(void) { return busy_detect; }
void modem_set_busy_reseed_on_hop(bool e) { busy_reseed = e; }
bool modem_get_busy_reseed_on_hop(void) { return busy_reseed; }
bool modem_rx_frame_in_flight(const char **m, uint64_t *ms) { (void)m; (void)ms; return false; }

/* ---- ring buffer (never reached by the control path) ---- */
size_t size_buffer(cbuf_handle_t c) { (void)c; return 0; }
int read_buffer(cbuf_handle_t c, uint8_t *d, size_t n) { (void)c; (void)d; (void)n; return 0; }
void clear_buffer(cbuf_handle_t c) { (void)c; }
int write_buffer(cbuf_handle_t c, uint8_t *d, size_t n) { (void)c; (void)d; (void)n; return 0; }
cbuf_handle_t circular_buf_init(uint8_t *b, size_t n) { (void)b; (void)n; return NULL; }

/* ---- kiss ---- */
int kiss_write_frame(uint8_t *a, int b, uint8_t cmd, uint8_t *c) { (void)a; (void)b; (void)cmd; (void)c; return 0; }
int kiss_read(uint8_t b, uint8_t *c) { (void)b; (void)c; return 0; }
void kiss_reset_state(void) { }
uint8_t kiss_last_command(void) { return CMD_DATA; }

/* ---- globals tcp_interfaces.c expects ---- */
cbuf_handle_t data_tx_buffer_arq = NULL;
cbuf_handle_t data_rx_buffer_arq = NULL;
cbuf_handle_t data_tx_buffer_broadcast = NULL;
cbuf_handle_t data_rx_buffer_broadcast = NULL;
_Atomic bool mercury_stop = false;
arq_info arq_conn = {0};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static char line[TCP_BLOCK_SIZE + 1];   /* as arq_reactor_thread's ctl_line */
    int line_len = 0;

    if (size < 1)
        return 0;
    /* Open queue: the critical-line retry loop would otherwise sleep 50 ms. */
    atomic_store(&tnc_txq_open, true);
    memset(&arq_conn, 0, sizeof(arq_conn));

    uint8_t k = data[0];
    data++; size--;
    while (size > 0)
    {
        k = (uint8_t)(k * 37u + 11u);
        size_t n = (size_t)(k % 48u) + 1;
        if (n > size)
            n = size;
        process_control_bytes(line, &line_len, data, (ssize_t)n);
        if (line_len < 0 || line_len > TCP_BLOCK_SIZE)
            abort();
        data += n; size -= n;
    }
    return 0;
}
