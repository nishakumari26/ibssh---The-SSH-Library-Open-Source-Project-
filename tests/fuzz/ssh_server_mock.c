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

#include "ssh_server_mock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LIBSSH_STATIC 1
#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

/* Fixed ed25519 key for all mock servers */
const char *ssh_mock_ed25519_key_pem =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
    "QyNTUxOQAAACBpFO8/JfYlIqg6+vqx1vDKWDqxJHxw4tBqnQfiOjf2zAAAAJgbsYq1G7GK\n"
    "tQAAAAtzc2gtZWQyNTUxOQAAACBpFO8/JfYlIqg6+vqx1vDKWDqxJHxw4tBqnQfiOjf2zA\n"
    "AAAEAkGaLvQwKMbGVRk2M8cz7gqWvpBKuHkuekJxIBQrUJl2kU7z8l9iUiqDr6+rHW8MpY\n"
    "OrEkfHDi0GqdB+I6N/bMAAAAEGZ1enotZWQyNTUxOS1rZXkBAgMEBQ==\n"
    "-----END OPENSSH PRIVATE KEY-----\n";

/* Internal server session data */
struct mock_session_data {
    ssh_channel channel;
    struct ssh_mock_server_config *config;
};

/* Auth callback - always accepts "none" auth */
static int mock_auth_none(ssh_session session, const char *user, void *userdata)
{
    (void)session;
    (void)user;
    (void)userdata;
    return SSH_AUTH_SUCCESS;
}

/* Channel open callback */
static ssh_channel mock_channel_open(ssh_session session, void *userdata)
{
    struct mock_session_data *sdata = (struct mock_session_data *)userdata;
    sdata->channel = ssh_channel_new(session);
    return sdata->channel;
}

/* Exec request callback - for SCP */
static int mock_channel_exec(ssh_session session,
                             ssh_channel channel,
                             const char *command,
                             void *userdata)
{
    struct mock_session_data *sdata = (struct mock_session_data *)userdata;
    (void)session;
    (void)command;

    if (sdata->config->exec_callback) {
        return sdata->config->exec_callback(channel,
                                            sdata->config->protocol_data,
                                            sdata->config->protocol_data_size,
                                            sdata->config->callback_userdata);
    }
    return SSH_OK;
}

/* Subsystem request callback - for SFTP */
static int mock_channel_subsystem(ssh_session session,
                                  ssh_channel channel,
                                  const char *subsystem,
                                  void *userdata)
{
    struct mock_session_data *sdata = (struct mock_session_data *)userdata;
    (void)session;
    (void)subsystem;

    if (sdata->config->subsystem_callback) {
        return sdata->config->subsystem_callback(
            channel,
            sdata->config->protocol_data,
            sdata->config->protocol_data_size,
            sdata->config->callback_userdata);
    }
    return SSH_OK;
}

/* Server thread implementation */
static void *server_thread_func(void *arg)
{
    struct ssh_mock_server_config *config =
        (struct ssh_mock_server_config *)arg;
    ssh_bind sshbind = NULL;
    ssh_session session = NULL;
    ssh_event event = NULL;
    struct mock_session_data sdata = {0};
    sdata.config = config;

    struct ssh_server_callbacks_struct server_cb = {
        .userdata = &sdata,
        .auth_none_function = mock_auth_none,
        .channel_open_request_session_function = mock_channel_open,
    };

    struct ssh_channel_callbacks_struct channel_cb = {
        .userdata = &sdata,
        .channel_exec_request_function = mock_channel_exec,
        .channel_subsystem_request_function = mock_channel_subsystem,
    };

    bool no = false;

    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        config->server_error = true;
        return NULL;
    }

    session = ssh_new();
    if (session == NULL) {
        ssh_bind_free(sshbind);
        config->server_error = true;
        return NULL;
    }

    const char *cipher = config->cipher ? config->cipher : "aes128-ctr";
    const char *hmac = config->hmac ? config->hmac : "hmac-sha1";

    ssh_bind_options_set(sshbind,
                         SSH_BIND_OPTIONS_HOSTKEY,
                         SSH_MOCK_HOSTKEY_PATH);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_CIPHERS_C_S, cipher);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_CIPHERS_S_C, cipher);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HMAC_C_S, hmac);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HMAC_S_C, hmac);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_PROCESS_CONFIG, &no);

    ssh_set_auth_methods(session, SSH_AUTH_METHOD_NONE);
    ssh_callbacks_init(&server_cb);
    ssh_set_server_callbacks(session, &server_cb);

    if (ssh_bind_accept_fd(sshbind, session, config->server_socket) != SSH_OK) {
        ssh_free(session);
        ssh_bind_free(sshbind);
        config->server_error = true;
        return NULL;
    }

    config->server_ready = true;

    event = ssh_event_new();
    if (event == NULL) {
        ssh_disconnect(session);
        ssh_free(session);
        ssh_bind_free(sshbind);
        return NULL;
    }

    if (ssh_handle_key_exchange(session) == SSH_OK) {
        ssh_event_add_session(event, session);

        for (int i = 0; i < 50 && !sdata.channel; i++) {
            ssh_event_dopoll(event, 1);
        }

        if (sdata.channel) {
            ssh_callbacks_init(&channel_cb);
            ssh_set_channel_callbacks(sdata.channel, &channel_cb);

            int max_iterations = 30;
            for (int iter = 0; iter < max_iterations &&
                               !ssh_channel_is_closed(sdata.channel) &&
                               !ssh_channel_is_eof(sdata.channel);
                 iter++) {
                if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
                    break;
                }
            }
        }
    }

    if (event)
        ssh_event_free(event);
    if (session) {
        ssh_disconnect(session);
        ssh_free(session);
    }
    if (sshbind)
        ssh_bind_free(sshbind);

    return NULL;
}

/* Public API - start mock SSH server */
int ssh_mock_server_start(struct ssh_mock_server_config *config,
                          pthread_t *thread)
{
    if (!config || !thread)
        return -1;

    config->server_ready = false;
    config->server_error = false;

    if (pthread_create(thread, NULL, server_thread_func, config) != 0) {
        return -1;
    }

    for (int i = 0; i < 50 && !config->server_ready && !config->server_error;
         i++) {
        usleep(100);
    }

    return config->server_error ? -1 : 0;
}

/* Generic protocol callback - sends raw fuzzer data for any protocol */
int ssh_mock_send_raw_data(void *channel,
                           const void *data,
                           size_t size,
                           void *userdata)
{
    (void)userdata;

    ssh_channel target_channel = (ssh_channel)channel;

    /* Send raw fuzzer data - let protocol parser interpret it */
    if (size > 0) {
        ssh_channel_write(target_channel, data, size);
    }

    /* Close channel to signal completion */
    ssh_channel_send_eof(target_channel);
    ssh_channel_close(target_channel);
    return SSH_OK;
}

/* Write fixed ed25519 host key to file */
int ssh_mock_write_hostkey(const char *path)
{
    FILE *fp = fopen(path, "wb");
    if (fp == NULL)
        return -1;

    size_t len = strlen(ssh_mock_ed25519_key_pem);
    size_t nwritten = fwrite(ssh_mock_ed25519_key_pem, 1, len, fp);
    fclose(fp);

    return (nwritten == len) ? 0 : -1;
}
