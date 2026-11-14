/* libFuzzer target: the INI configuration reader and writer.
 *
 * Copyright (C) 2026 Rhizomatica
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Input up to the first NUL is written out as the INI file and read with
 * cfg_read() (iniparser underneath). Any bytes after that NUL go into
 * input_device as-is, the way the UI sets a device name it was handed. The
 * result is written with cfg_write() and read back.
 *
 * With FUZZ_CFG_ROUNDTRIP=1 the harness also asserts the round trip keeps
 * every string field. It does not today: cfg_escape_str() escapes only '\'
 * and '"', so a value carrying a newline (or a CR) ends its line early and
 * the rest is read as the next line of the file -- a key the value chose.
 * Off by default so the campaign keeps looking for memory errors.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cfg_utils.h"

static char in_path[256], out_path[256];

static void make_paths(void)
{
    if (in_path[0])
        return;
    const char *t = getenv("TMPDIR");
    if (!t || !*t) t = "/tmp";
    snprintf(in_path, sizeof(in_path), "%s/fuzz_cfg_in_%d.ini", t, (int)getpid());
    snprintf(out_path, sizeof(out_path), "%s/fuzz_cfg_out_%d.ini", t, (int)getpid());
}

static void same(const char *field, const char *a, const char *b)
{
    if (strcmp(a, b) != 0)
    {
        fprintf(stderr, "cfg round trip changed %s:\n  wrote [%s]\n  read  [%s]\n", field, a, b);
        abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    make_paths();

    const uint8_t *nul = memchr(data, 0, size);
    size_t ini_len = nul ? (size_t)(nul - data) : size;

    FILE *f = fopen(in_path, "wb");
    if (!f)
        abort();
    fwrite(data, 1, ini_len, f);
    fclose(f);

    static mercury_config a, b;
    cfg_set_defaults(&a);
    (void)cfg_read(&a, in_path);
    if (nul)
    {
        size_t n = size - ini_len - 1;
        if (n >= sizeof(a.input_device)) n = sizeof(a.input_device) - 1;
        memcpy(a.input_device, nul + 1, n);
        a.input_device[n] = '\0';
    }

    if (cfg_write(&a, out_path))
    {
        cfg_set_defaults(&b);
        bool ok = cfg_read(&b, out_path);
        if (getenv("FUZZ_CFG_ROUNDTRIP"))
        {
            if (!ok)
                abort();
            same("ui_tls_cert", a.tls_cert, b.tls_cert);
            same("ui_tls_key", a.tls_key, b.tls_key);
            same("input_device", a.input_device, b.input_device);
            same("output_device", a.output_device, b.output_device);
            same("input_device_name", a.input_device_name, b.input_device_name);
            same("output_device_name", a.output_device_name, b.output_device_name);
            same("callsign", a.callsign, b.callsign);
            same("ptt device", a.ptt.device, b.ptt.device);
            same("ptt hamlib_conf", a.ptt.hamlib_conf, b.ptt.hamlib_conf);
            same("store path", a.store_path, b.store_path);
        }
    }
    unlink(in_path);
    unlink(out_path);
    return 0;
}
