/* libFuzzer target: the persisted message store (JSONL) load path.
 *
 * Copyright (C) 2026 Rhizomatica
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Byte 0 picks the ring size (1..16, small so the trim-and-rewrite path runs);
 * the rest is written out as the store file and loaded by msg_store_init().
 * Then the readers the UI uses run over what was loaded, one message is
 * appended, and the store is shut down (which may rewrite the file again).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "message_store.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static char path[256];
    if (!path[0])
    {
        const char *t = getenv("TMPDIR");
        snprintf(path, sizeof(path), "%s/fuzz_msg_store_%d.jsonl",
                 t && *t ? t : "/tmp", (int)getpid());
    }
    if (size < 1)
        return 0;

    FILE *f = fopen(path, "wb");
    if (!f)
        abort();
    fwrite(data + 1, 1, size - 1, f);
    fclose(f);

    if (msg_store_init(path, 1 + data[0] % 16) == 0)
    {
        size_t count = 0, len = 0;
        char *snap = msg_store_snapshot(&count, &len);
        if (snap && strlen(snap) != len)
            abort();
        free(snap);

        char buf[64];
        for (size_t i = 0; i < count; i++)
            (void)msg_store_get(i, buf, sizeof(buf));

        uint64_t last = 0, seq = 0;
        size_t guard = 0;
        do {   /* page through in small chunks, as the UI history does */
            seq = last;
            (void)msg_store_since(seq, buf, sizeof(buf), &last);
        } while (last != seq && ++guard < 64);

        msg_store_append("arq", "rx", "K1ABC", "73 de K1ABC");
        (void)msg_store_last_seq();
        msg_store_shutdown();
    }
    unlink(path);
    return 0;
}
