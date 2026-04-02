/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2018 by Red Hat, Inc.
 *
 * Author: Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include <stdbool.h>
#include <fcntl.h>

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

struct server_state_st {
    /* Arguments */
    char *address;
    int  port;

    char *ecdsa_key;
    char *ed25519_key;
    char *rsa_key;
    char *host_key;

    int  verbosity;
    int  auth_methods;
    bool with_pcap;

    char *pcap_file;

    char *expected_username;
    char *expected_password;

    char *config_file;
    bool parse_global_config;

    char *log_file;
    bool gssapi_key_exchange;
    const char *gssapi_key_exchange_algs;

    /* State */
    int  max_tries;
    int  error;

    struct ssh_server_callbacks_struct *server_cb;
    struct ssh_channel_callbacks_struct *channel_cb;

    /* Callback to handle the session, should block until disconnected */
    void (*handle_session)(ssh_event event,
                           ssh_session session,
                           struct server_state_st *state);
};

/**
 * @brief Free a server state struct.
 *
 * Frees all memory inside server_state_st using SAFE_FREE.
 *
 * @param[in] state       The server_state_st struct to free.
 */
void free_server_state(struct server_state_st *state);

/**
 * @brief Run a SSH server based on a server state struct.
 *
 * Takes a server_state_st struct, validates required fields, and starts
 * listening for connections. For each client, it forks a child process
 * that calls handle_session. Blocks until SIGTERM is received.
 *
 * @param[in] state       The server configuration struct.
 *
 * @return SSH_OK on success, SSH_ERROR if an error occurred.
 *
 * @note This function blocks until SIGTERM is received.
 * @note The state is freed internally; do not use after calling.
 * @note If state->log_file is set, stdout/stderr are redirected to it.
 *
 * @see fork_run_server()
 * @see free_server_state()
 */
int run_server(struct server_state_st *state);

/**
 * @brief Fork and run an SSH server in non-blocking mode.
 *
 * Forks a child process that calls run_server(). The parent returns
 * immediately with the child's PID. Designed for tests that need
 * a server running in the background.
 *
 * @param[in] state           The server_state_st struct passed to run_server().
 * @param[in] free_state      Callback to free parent's test data in the child.
 * @param[in] userdata        Pointer passed to free_state.
 *
 * @return Child PID on success, -1 on error.
 *
 * @note The parent should send SIGTERM to the child PID when done.
 * @note The state is freed by the child process via run_server().
 *
 * @see run_server()
 */
pid_t
fork_run_server(struct server_state_st *state,
                void (*free_state) (void **userdata),
                void *userdata);
