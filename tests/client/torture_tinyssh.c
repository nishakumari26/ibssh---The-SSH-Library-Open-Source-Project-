/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2026 by Your Bulitha Kawushika De Zoysa
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
#include "tests_config.h"

#define LIBSSH_STATIC

#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include "torture.h"

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TINYSSH_PIDFILE "tinyssh.pid"
#define TINYSSH_PORT    22

/* TINYSSH Server Setup and Teardown */

static int tinyssh_setup(void **state)
{
    struct torture_state *s = NULL;
    char cmd[4096];
    char pid_path[1024];
    int rc;

    torture_setup_socket_dir(state);
    s = *state;

    snprintf(pid_path,
             sizeof(pid_path),
             "%s/%s",
             s->socket_dir,
             TINYSSH_PIDFILE);
    free(s->srv_pidfile);
    s->srv_pidfile = strdup(pid_path);
    if (s->srv_pidfile == NULL) {
        return -1;
    }

    snprintf(cmd,
             sizeof(cmd),
             "%s -l %s %d -k -c \"%s %s -v %s\" "
             "> %s/tinyssh.log 2>&1 & echo $! > %s",
             NCAT_EXECUTABLE,
             TORTURE_SSH_SERVER,
             TINYSSH_PORT,
             TINYSSHD_EXECUTABLE,
             "",
             TINYSSH_KEYS_DIR,
             s->socket_dir,
             s->srv_pidfile);

    SSH_LOG(SSH_LOG_DEBUG, "Executing: %s\n", cmd);

    rc = system(cmd);
    if (rc != 0) {
        return -1;
    }

    rc = torture_wait_for_daemon(15);
    if (rc != 0) {
        return -1;
    }

    return 0;
}

static int tinyssh_teardown(void **state)
{
    struct torture_state *s = *state;
    torture_terminate_process(s->srv_pidfile);
    torture_teardown_socket_dir(state);
    return 0;
}

/* LIBSSH Client Setup and Teardown */

static int session_setup(void **state)
{
    struct torture_state *s = *state;
    int verbosity = torture_libssh_verbosity();
    bool process_config = false;
    int port = TINYSSH_PORT;
    struct passwd *pwd = NULL;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    ssh_options_set(s->ssh.session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(s->ssh.session, SSH_OPTIONS_USER, "bob");
    ssh_options_set(s->ssh.session,
                    SSH_OPTIONS_PROCESS_CONFIG,
                    &process_config);

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;
    if (s->ssh.session) {
        ssh_disconnect(s->ssh.session);
        ssh_free(s->ssh.session);
    }
    return 0;
}

/* Algorithms Helper */

static void test_specific_algorithm(ssh_session session,
                                    const char *kex,
                                    const char *cipher,
                                    const char *hostkey,
                                    int expected_rc)
{
    int rc;
    char data[256];
    size_t len_to_test[] = {1,  2,  3,  4,  5,  6,  7,  8,  10,  12,  15,
                            16, 20, 31, 32, 33, 63, 64, 65, 100, 127, 128};
    unsigned int i;

    /* Set Key Exchange */
    if (kex != NULL) {
        rc = ssh_options_set(session, SSH_OPTIONS_KEY_EXCHANGE, kex);
        assert_ssh_return_code(session, rc);
    }

    /* Set Ciphers */
    if (cipher != NULL) {
        rc = ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, cipher);
        assert_ssh_return_code(session, rc);
        rc = ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, cipher);
        assert_ssh_return_code(session, rc);
    }

    /* Set Hostkey */
    if (hostkey != NULL) {
        rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, hostkey);
        assert_ssh_return_code(session, rc);
    }

    rc = ssh_connect(session);

    if (expected_rc == SSH_OK) {
        assert_ssh_return_code(session, rc);

        if (cipher != NULL) {
            const char *used_cipher = ssh_get_cipher_out(session);
            assert_non_null(used_cipher);
            assert_string_equal(used_cipher, cipher);
        }

        if (hostkey != NULL) {
            ssh_key pubkey = NULL;
            const char *type_str = NULL;

            rc = ssh_get_server_publickey(session, &pubkey);
            assert_int_equal(rc, SSH_OK);
            assert_non_null(pubkey);

            type_str = ssh_key_type_to_char(ssh_key_type(pubkey));
            assert_non_null(type_str);
            assert_string_equal(type_str, hostkey);
            ssh_key_free(pubkey);
        }

        memset(data, 0, sizeof(data));
        for (i = 0; i < (sizeof(len_to_test) / sizeof(size_t)); i++) {
            memset(data, 'A', len_to_test[i]);
            ssh_send_ignore(session, data);
            ssh_handle_packets(session, 50);
        }

        rc = ssh_userauth_none(session, NULL);
        if (rc != SSH_OK) {
            rc = ssh_get_error_code(session);
            assert_int_equal(rc, SSH_REQUEST_DENIED);
        }

    } else {
        assert_int_not_equal(rc, SSH_OK);
    }
}

/* Test Cases */

static void torture_tinyssh_curve25519(void **state)
{
    struct torture_state *s = *state;
    test_specific_algorithm(s->ssh.session,
                            "curve25519-sha256",
                            NULL,
                            NULL,
                            SSH_OK);
}

static void torture_tinyssh_curve25519_libssh(void **state)
{
    struct torture_state *s = *state;
    test_specific_algorithm(s->ssh.session,
                            "curve25519-sha256@libssh.org",
                            NULL,
                            NULL,
                            SSH_OK);
}

static void torture_tinyssh_sntrup761(void **state)
{
    struct torture_state *s = *state;
    test_specific_algorithm(s->ssh.session,
                            "sntrup761x25519-sha512@openssh.com",
                            NULL,
                            NULL,
                            SSH_OK);
}

static void torture_tinyssh_chacha20(void **state)
{
    struct torture_state *s = *state;
    test_specific_algorithm(s->ssh.session,
                            NULL,
                            "chacha20-poly1305@openssh.com",
                            NULL,
                            SSH_OK);
}

static void torture_tinyssh_neg_cipher(void **state)
{
    struct torture_state *s = *state;

    /* TinySSH does not support older ciphers like aes128-cbc.*/

    test_specific_algorithm(s->ssh.session,
                            NULL,
                            "aes128-cbc",
                            NULL,
                            SSH_ERROR);
}

static void torture_tinyssh_hostkey_ed25519(void **state)
{
    struct torture_state *s = *state;
    test_specific_algorithm(s->ssh.session, NULL, NULL, "ssh-ed25519", SSH_OK);
}

static void torture_tinyssh_neg_kex(void **state)
{
    struct torture_state *s = *state;

    /* TinySSH does not support legacy Diffie-Hellman groups or NIST curves.*/

    test_specific_algorithm(s->ssh.session,
                            "diffie-hellman-group1-sha1",
                            NULL,
                            NULL,
                            SSH_ERROR);
}

int torture_run_tests(void)
{
    int rc;

    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_tinyssh_curve25519,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_tinyssh_curve25519_libssh,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_tinyssh_sntrup761,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_tinyssh_hostkey_ed25519,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_tinyssh_chacha20,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_tinyssh_neg_cipher,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_tinyssh_neg_kex,
                                        session_setup,
                                        session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, tinyssh_setup, tinyssh_teardown);

    ssh_finalize();
    return rc;
}