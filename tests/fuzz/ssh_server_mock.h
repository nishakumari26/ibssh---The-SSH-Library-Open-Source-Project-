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

#ifndef SSH_SERVER_MOCK_H
#define SSH_SERVER_MOCK_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

/* Server callback type */
typedef int (*ssh_mock_callback_fn)(void *channel,
                                    const void *data,
                                    size_t size,
                                    void *userdata);

/* Mock server configuration */
struct ssh_mock_server_config {
    const uint8_t *protocol_data;
    size_t protocol_data_size;
    ssh_mock_callback_fn exec_callback;
    ssh_mock_callback_fn subsystem_callback;
    void *callback_userdata;
    const char *cipher;
    const char *hmac;
    int server_socket;
    int client_socket;
    bool server_ready;
    bool server_error;
};

/* Public API functions */
int ssh_mock_server_start(struct ssh_mock_server_config *config,
                          pthread_t *thread);
int ssh_mock_send_raw_data(void *channel,
                           const void *data,
                           size_t size,
                           void *userdata);
int ssh_mock_write_hostkey(const char *path);

/* Fixed ed25519 key constant */
extern const char *ssh_mock_ed25519_key_pem;

/* Centralized hostkey path used by all mock servers */
#define SSH_MOCK_HOSTKEY_PATH "/tmp/libssh_mock_fuzz_key"

#endif
