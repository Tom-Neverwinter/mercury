/* libFuzzer target: Hermes Lite 2 UDP packets off the network.
 *
 * Copyright (C) 2026 Rhizomatica
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The HL2 parsers are static inline in audioio/hl2_wire.h, so including the
 * header reaches them without hl2.c's sockets and threads. Each datagram goes
 * where hl2.c sends it: hl2_wire_parse_discovery() (hl2_discover/find_radio)
 * and hl2_wire_parse_ep6() (the transport thread), and an EP6 packet's I/Q
 * on through hl2_rx_process(), as the transport does.
 *
 * Input: datagrams as [len lo] [len hi] [len bytes], len capped at the 2048
 * bytes hl2.c receives into. Each is copied to a buffer of exactly its size.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hl2_wire.h"
#include "hl2_dsp.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static hl2_rx rx;
    hl2_wire_status st = { 0 };
    float iq[2 * HL2_WIRE_PKT_SAMPLES];
    int32_t audio[HL2_WIRE_PKT_SAMPLES / HL2_DSP_L + HL2_DSP_BLOCK];

    hl2_rx_init(&rx);
    size_t i = 0;
    while (i + 2 <= size)
    {
        size_t n = (size_t)data[i] | ((size_t)data[i + 1] << 8);
        i += 2;
        if (n > 2048) n = 2048;
        if (n > size - i) n = size - i;
        uint8_t *pkt = malloc(n ? n : 1);
        memcpy(pkt, data + i, n);
        i += n;

        hl2_wire_disc d;
        (void)hl2_wire_parse_discovery(pkt, n, &d);

        uint32_t seq;
        if (hl2_wire_parse_ep6(pkt, n, &seq, iq, &st) == 0)
        {
            size_t k = hl2_rx_process(&rx, iq, HL2_WIRE_PKT_SAMPLES, seq & 1, audio);
            if (k > sizeof(audio) / sizeof(audio[0]))
                abort();
        }
        free(pkt);
    }
    return 0;
}
