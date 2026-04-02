/*
 * Copyright 2026 libssh authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LIBSSH_STATIC 1
#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/sftp.h"
#include "libssh/sftp_priv.h"

#include "nallocinc.c"

/* SFTP protocol version constants */
#define SFTP_PROTOCOL_VERSION_3 3
#define SFTP_PROTOCOL_VERSION_4 4

/* Flags for sftp_parse_attr expectname parameter */
#define SFTP_EXPECT_NAME 1
#define SFTP_NO_NAME 0

/*
 * Helper to create a minimal sftp_session for fuzzing.
 * We don't use sftp_new() as it requires a real SSH connection.
 */
static sftp_session create_minimal_sftp_session(ssh_session session)
{
    sftp_session sftp;

    sftp = calloc(1, sizeof(struct sftp_session_struct));
    if (sftp == NULL) {
        return NULL;
    }
    sftp->session = session;

    return sftp;
}

static void _fuzz_finalize(void)
{
    ssh_finalize();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;

    nalloc_init(*argv[0]);

    ssh_init();

    atexit(_fuzz_finalize);

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ssh_session session = NULL;
    sftp_session sftp = NULL;
    ssh_buffer buffer = NULL;
    sftp_attributes attr = NULL;
    int versions[] = {
        SFTP_PROTOCOL_VERSION_3, SFTP_PROTOCOL_VERSION_3,
        SFTP_PROTOCOL_VERSION_4, SFTP_PROTOCOL_VERSION_4
    };
    int expectnames[] = {SFTP_NO_NAME, SFTP_EXPECT_NAME, SFTP_NO_NAME, SFTP_EXPECT_NAME};
    size_t i;

    /* Minimum bytes for a valid SFTP message */
    if (size == 0) {
        return 0;
    }

    assert(nalloc_start(data, size) > 0);

    /* Allocate shared resources once for all test iterations */
    session = ssh_new();
    if (session == NULL) {
        goto cleanup;
    }

    sftp = create_minimal_sftp_session(session);
    if (sftp == NULL) {
        goto cleanup;
    }

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        goto cleanup;
    }

    /* Main fuzzing target: sftp_parse_attr */
    /* Parses untrusted SFTP messages from client */
    /* Test all combinations (v3/v4, with/without name) */
    for (i = 0; i < ARRAY_SIZE(versions); i++) {
        sftp->version = versions[i];

        /* Reset and repopulate buffer for each iteration */
        ssh_buffer_reinit(buffer);
        if (ssh_buffer_add_data(buffer, data, size) == SSH_OK) {
            attr = sftp_parse_attr(sftp, buffer, expectnames[i]);
            sftp_attributes_free(attr);
            attr = NULL;
        }
    }

cleanup:
    ssh_buffer_free(buffer);
    free(sftp);
    ssh_free(session);
    nalloc_end();

    return 0;
}
