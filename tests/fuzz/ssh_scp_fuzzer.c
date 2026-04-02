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

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LIBSSH_STATIC 1
#include <libssh/libssh.h>
#include <libssh/scp.h>

#include "nallocinc.c"
#include "ssh_server_mock.h"

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
    ssh_mock_write_hostkey(SSH_MOCK_HOSTKEY_PATH);
    return 0;
}

/* Helper function to test one cipher/HMAC combination */
static int test_scp_with_cipher(const uint8_t *data,
                                size_t size,
                                const char *cipher,
                                const char *hmac)
{
    int socket_fds[2] = {-1, -1};
    ssh_session client_session = NULL;
    ssh_scp scp = NULL, scp_recursive = NULL;
    char buf[256] = {0};
    pthread_t srv_thread;

    /* Configure mock SSH server with fuzzer data */
    struct ssh_mock_server_config server_config = {
        .protocol_data = data,
        .protocol_data_size = size,
        .exec_callback = ssh_mock_send_raw_data,
        .subsystem_callback = NULL,
        .callback_userdata = NULL,
        .cipher = cipher,
        .hmac = hmac,
        .server_socket = -1,
        .client_socket = -1,
        .server_ready = false,
        .server_error = false,
    };

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds) != 0) {
        goto cleanup;
    }

    server_config.server_socket = socket_fds[0];
    server_config.client_socket = socket_fds[1];

    if (ssh_mock_server_start(&server_config, &srv_thread) != 0) {
        goto cleanup;
    }

    client_session = ssh_new();
    if (client_session == NULL) {
        goto cleanup_thread;
    }

    /* Configure client with specified cipher/HMAC */
    ssh_options_set(client_session, SSH_OPTIONS_FD, &socket_fds[1]);
    ssh_options_set(client_session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(client_session, SSH_OPTIONS_USER, "fuzz");
    ssh_options_set(client_session, SSH_OPTIONS_CIPHERS_C_S, cipher);
    ssh_options_set(client_session, SSH_OPTIONS_CIPHERS_S_C, cipher);
    ssh_options_set(client_session, SSH_OPTIONS_HMAC_C_S, hmac);
    ssh_options_set(client_session, SSH_OPTIONS_HMAC_S_C, hmac);

    /* Set timeout for operations (1 second) */
    long timeout = 1;
    ssh_options_set(client_session, SSH_OPTIONS_TIMEOUT, &timeout);

    if (ssh_connect(client_session) != SSH_OK) {
        goto cleanup_thread;
    }

    if (ssh_userauth_none(client_session, NULL) != SSH_AUTH_SUCCESS) {
        goto cleanup_thread;
    }

    scp = ssh_scp_new(client_session, SSH_SCP_READ, "/tmp/fuzz");
    if (scp == NULL) {
        goto cleanup_thread;
    }

    if (ssh_scp_init(scp) != SSH_OK) {
        goto cleanup_thread;
    }

    if (size > 0) {
        size_t copy_size = size < sizeof(buf) ? size : sizeof(buf);
        memcpy(buf, data, copy_size);
    }

    /* Fuzz all SCP API functions in read mode */
    ssh_scp_pull_request(scp);
    ssh_scp_request_get_filename(scp);
    ssh_scp_request_get_permissions(scp);
    ssh_scp_request_get_size64(scp);
    ssh_scp_request_get_size(scp);
    ssh_scp_request_get_warning(scp);
    ssh_scp_accept_request(scp);
    ssh_scp_deny_request(scp, "Denied by fuzzer");
    ssh_scp_read(scp, buf, sizeof(buf));

    /* Final fuzz of scp pull request after all the calls */
    ssh_scp_pull_request(scp);

    /* Fuzz SCP in write/upload + recursive directory mode. */
    scp_recursive = ssh_scp_new(client_session,
                                SSH_SCP_WRITE | SSH_SCP_RECURSIVE,
                                "/tmp/fuzz-recursive");
    if (scp_recursive != NULL) {
        if (ssh_scp_init(scp_recursive) == SSH_OK) {
            ssh_scp_push_directory(scp_recursive, "fuzz-dir", 0755);
            ssh_scp_push_file(scp_recursive, "fuzz-file", sizeof(buf), 0644);
            ssh_scp_write(scp_recursive, buf, sizeof(buf));
            ssh_scp_leave_directory(scp_recursive);
        }
    }

cleanup_thread:
    pthread_join(srv_thread, NULL);

cleanup:
    if (scp_recursive != NULL) {
        ssh_scp_close(scp_recursive);
        ssh_scp_free(scp_recursive);
    }
    if (scp) {
        ssh_scp_close(scp);
        ssh_scp_free(scp);
    }
    if (client_session) {
        ssh_disconnect(client_session);
        ssh_free(client_session);
    }
    if (socket_fds[0] >= 0)
        close(socket_fds[0]);
    if (socket_fds[1] >= 0)
        close(socket_fds[1]);

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    assert(nalloc_start(data, size) > 0);

    /* Test all cipher/HMAC combinations exhaustively */
    const char *ciphers[] = {
        "none",
        "aes128-ctr",
        "aes256-ctr",
        "aes128-cbc",
    };

    const char *hmacs[] = {
        "none",
        "hmac-sha1",
        "hmac-sha2-256",
    };

    int num_ciphers = sizeof(ciphers) / sizeof(ciphers[0]);
    int num_hmacs = sizeof(hmacs) / sizeof(hmacs[0]);

    for (int i = 0; i < num_ciphers; i++) {
        for (int j = 0; j < num_hmacs; j++) {
            test_scp_with_cipher(data, size, ciphers[i], hmacs[j]);
        }
    }

    nalloc_end();
    return 0;
}
