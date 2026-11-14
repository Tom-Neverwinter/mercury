/* libFuzzer target: broadcast file receiver (RaptorQ carousel off the air).
 *
 * Copyright (C) 2026 Rhizomatica
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The input is cut into DATAC4-sized frames (54 bytes, one 41-byte symbol each)
 * and fed to bcast_file_rx_frame(). Whatever the receiver decides to write must
 * land directly inside its download directory: the download dir is nested two
 * levels deep in a private temp tree, and after each input the harness checks
 * that nothing appeared beside it or above it, and that nothing inside it is a
 * directory. Then the files are removed so inputs stay independent.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

#include "bcast_file.h"

#define MODE 3   /* DATAC4 */

static char root[256], mid[300], dir[350];

static void setup_dirs(void)
{
    if (root[0])
        return;
    const char *t = getenv("TMPDIR");
    snprintf(root, sizeof(root), "%s/fuzz_bcast_XXXXXX", t && *t ? t : "/tmp");
    if (!mkdtemp(root))
        abort();
    snprintf(mid, sizeof(mid), "%s/a", root);
    snprintf(dir, sizeof(dir), "%s/a/dl", root);
    if (mkdir(mid, 0700) != 0 || mkdir(dir, 0700) != 0)
        abort();
}

/* Directory p must hold exactly the one entry `only`. */
static void expect_only(const char *p, const char *only)
{
    DIR *d = opendir(p);
    if (!d)
        abort();
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
    {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        if (strcmp(e->d_name, only) != 0)
        {
            fprintf(stderr, "file escaped the download dir: %s/%s\n", p, e->d_name);
            abort();
        }
    }
    closedir(d);
}

static void check_and_clean(void)
{
    expect_only(root, "a");
    expect_only(mid, "dl");

    DIR *d = opendir(dir);
    if (!d)
        abort();
    struct dirent *e;
    char path[700];
    while ((e = readdir(d)) != NULL)
    {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode))
        {
            fprintf(stderr, "non-regular entry in the download dir: %s\n", path);
            abort();
        }
        unlink(path);
    }
    closedir(d);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    setup_dirs();

    char err[128];
    bcast_file_rx_t *rx = bcast_file_rx_open(MODE, dir, err, sizeof(err));
    if (!rx)
        abort();
    const size_t fs = (size_t)bcast_file_mode_frame_size(MODE);

    for (size_t off = 0; off + fs <= size; off += fs)
    {
        if (bcast_file_rx_frame(rx, data + off, fs) == BCAST_RX_COMPLETE)
        {
            /* The reported path must be <dir>/<plain name>. */
            const char *p = bcast_file_rx_last_path(rx);
            size_t dl = strlen(dir);
            if (strncmp(p, dir, dl) != 0 || p[dl] != '/' || strchr(p + dl + 1, '/'))
                abort();
            if (getenv("FUZZ_VERBOSE"))
                fprintf(stderr, "complete: %s\n", p);
        }
    }
    bcast_file_rx_close(rx);
    check_and_clean();
    return 0;
}
