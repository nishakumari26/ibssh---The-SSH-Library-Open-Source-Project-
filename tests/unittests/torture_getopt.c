#include "config.h"

#define LIBSSH_STATIC

#include "libssh/getopt.h"
#include "torture.h"

#include <string.h>

/*
 * Dedicated unit tests for the getopt abstraction layer.
 * On systems with native getopt, this tests the system implementation.
 * On MSVC, this tests the bundled fallback in src/external/getopt.c.
 */

static int setup(void **state)
{
    (void)state;
    /* Reset getopt state before each test */
    optind = 1;
    optopt = 0;
    optarg = NULL;
    opterr = 1;
    return 0;
}

static void torture_getopt_basic(void **state)
{
    const char *argv[] = {"prog", "-a", "-b", NULL};
    int argc = 3;
    int opt;

    (void)state;

    opt = getopt(argc, (char *const *)argv, "ab");
    assert_int_equal(opt, 'a');

    opt = getopt(argc, (char *const *)argv, "ab");
    assert_int_equal(opt, 'b');

    opt = getopt(argc, (char *const *)argv, "ab");
    assert_int_equal(opt, -1);
}

static void torture_getopt_with_argument(void **state)
{
    const char *argv[] = {"prog", "-f", "filename", NULL};
    int argc = 3;
    int opt;

    (void)state;

    opt = getopt(argc, (char *const *)argv, "f:");
    assert_int_equal(opt, 'f');
    assert_non_null(optarg);
    assert_string_equal(optarg, "filename");

    opt = getopt(argc, (char *const *)argv, "f:");
    assert_int_equal(opt, -1);
}

static void torture_getopt_optional_argument(void **state)
{
    int opt;

    (void)state;

    /* "f::" with no attached value: optarg must be NULL */
    {
        const char *argv[] = {"prog", "-f", NULL};
        int argc = 2;

        optind = 1;
        optarg = NULL;

        opt = getopt(argc, (char *const *)argv, "f::");
        assert_int_equal(opt, 'f');
        assert_null(optarg);
        assert_int_equal(optind, 2);
    }

    /* "f::" with attached value in same argv element: "-ffile" */
    {
        const char *argv[] = {"prog", "-ffile", NULL};
        int argc = 2;

        optind = 1;
        optarg = NULL;

        opt = getopt(argc, (char *const *)argv, "f::");
        assert_int_equal(opt, 'f');
        assert_non_null(optarg);
        assert_string_equal(optarg, "file");
        assert_int_equal(optind, 2);
    }

    /* "f::" with value as separate argv element: optarg should be NULL
     * because the GNU :: extension only consumes attached arguments */
    {
        const char *argv[] = {"prog", "-f", "file", NULL};
        int argc = 3;

        optind = 1;
        optarg = NULL;

        opt = getopt(argc, (char *const *)argv, "f::");
        assert_int_equal(opt, 'f');
        assert_null(optarg);
        assert_int_equal(optind, 2);
    }
}

static void torture_getopt_unknown_option(void **state)
{
    const char *argv[] = {"prog", "-z", NULL};
    int argc = 2;
    int opt;

    (void)state;

    opterr = 0; /* suppress error output */
    opt = getopt(argc, (char *const *)argv, "ab");
    assert_int_equal(opt, '?');
    assert_int_equal(optopt, 'z');
}

static void torture_getopt_missing_argument(void **state)
{
    const char *argv[] = {"prog", "-f", NULL};
    int argc = 2;
    int opt;

    (void)state;

    opterr = 0;
    opt = getopt(argc, (char *const *)argv, "f:");
    assert_int_equal(opt, '?');
    assert_int_equal(optopt, 'f');
}

static void torture_getopt_missing_argument_colon(void **state)
{
    const char *argv[] = {"prog", "-f", NULL};
    int argc = 2;
    int opt;

    (void)state;

    /* Leading ':' in optstring: missing argument returns ':' not '?' */
    opterr = 0;
    opt = getopt(argc, (char *const *)argv, ":f:");
    assert_int_equal(opt, ':');
    assert_int_equal(optopt, 'f');
    /* Note: optind value after error is implementation-defined,
     * differs between glibc (2), musl (3), and FreeBSD (2) */
}

static void torture_getopt_double_dash(void **state)
{
    const char *argv[] = {"prog", "--", "-a", NULL};
    int argc = 3;
    int opt;

    (void)state;

    opt = getopt(argc, (char *const *)argv, "a");
    assert_int_equal(opt, -1);
    assert_int_equal(optind, 2);
}

static void torture_getopt_combined_options(void **state)
{
    const char *argv[] = {"prog", "-abc", NULL};
    int argc = 2;
    int opt;

    (void)state;

    opt = getopt(argc, (char *const *)argv, "abc");
    assert_int_equal(opt, 'a');

    opt = getopt(argc, (char *const *)argv, "abc");
    assert_int_equal(opt, 'b');

    opt = getopt(argc, (char *const *)argv, "abc");
    assert_int_equal(opt, 'c');

    opt = getopt(argc, (char *const *)argv, "abc");
    assert_int_equal(opt, -1);
}

static void torture_getopt_optind_advance(void **state)
{
    const char *argv[] = {"prog", "-a", "nonoption", NULL};
    int argc = 3;
    int opt;

    (void)state;

    opt = getopt(argc, (char *const *)argv, "a");
    assert_int_equal(opt, 'a');
    assert_int_equal(optind, 2);

    opt = getopt(argc, (char *const *)argv, "a");
    assert_int_equal(opt, -1);
    /* optind should point to the non-option argument */
    assert_int_equal(optind, 2);
}

static void torture_getopt_reset(void **state)
{
    const char *argv[] = {"prog", "-a", "-b", NULL};
    int argc = 3;
    int opt;

    (void)state;

    opt = getopt(argc, (char *const *)argv, "ab");
    assert_int_equal(opt, 'a');

    /* Reset and parse again */
    optind = 1;
    opt = getopt(argc, (char *const *)argv, "ab");
    assert_int_equal(opt, 'a');
}

static void torture_getopt_no_options(void **state)
{
    const char *argv[] = {"prog", NULL};
    int argc = 1;
    int opt;

    (void)state;

    opt = getopt(argc, (char *const *)argv, "ab");
    assert_int_equal(opt, -1);
}

int torture_run_tests(void)
{
    int rc;

    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(torture_getopt_basic, setup),
        cmocka_unit_test_setup(torture_getopt_with_argument, setup),
        cmocka_unit_test_setup(torture_getopt_optional_argument, setup),
        cmocka_unit_test_setup(torture_getopt_unknown_option, setup),
        cmocka_unit_test_setup(torture_getopt_missing_argument, setup),
        cmocka_unit_test_setup(torture_getopt_missing_argument_colon, setup),
        cmocka_unit_test_setup(torture_getopt_double_dash, setup),
        cmocka_unit_test_setup(torture_getopt_combined_options, setup),
        cmocka_unit_test_setup(torture_getopt_optind_advance, setup),
        cmocka_unit_test_setup(torture_getopt_reset, setup),
        cmocka_unit_test_setup(torture_getopt_no_options, setup),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();

    return rc;
}
