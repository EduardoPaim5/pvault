#define _POSIX_C_SOURCE 200809L

#include "test.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
static unsigned cases_run;
static unsigned checks_run;

static void remove_tree_impl(const char *path)
{
    struct stat info;
    DIR *directory;
    struct dirent *entry;

    if (lstat(path, &info) != 0) {
        return;
    }
    if (!S_ISDIR(info.st_mode)) {
        (void)unlink(path);
        return;
    }

    directory = opendir(path);
    if (directory == NULL) {
        return;
    }
    while ((entry = readdir(directory)) != NULL) {
        char child[PATH_MAX];
        int written;

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        written = snprintf(child, sizeof child, "%s/%s", path, entry->d_name);
        if (written < 0 || (size_t)written >= sizeof child) {
            continue;
        }
        remove_tree_impl(child);
    }
    (void)closedir(directory);
    (void)rmdir(path);
}

void pv_test_run(const char *name, pv_test_function function)
{
    int failures_before = failures;

    ++cases_run;
    (void)fprintf(stderr, "[ RUN      ] %s\n", name);
    function();
    if (failures == failures_before) {
        (void)fprintf(stderr, "[       OK ] %s\n", name);
    } else {
        (void)fprintf(stderr, "[  FAILED  ] %s\n", name);
    }
}

void pv_test_check(bool condition, const char *expression, const char *file, int line)
{
    ++checks_run;
    if (!condition) {
        ++failures;
        (void)fprintf(stderr, "%s:%d: check failed: %s\n", file, line, expression);
    }
}

void pv_test_check_status(
    const pv_status actual,
    const pv_status expected,
    const char *const actual_expression,
    const char *const file,
    const int line
)
{
    ++checks_run;
    if (actual != expected) {
        ++failures;
        (void)fprintf(
            stderr,
            "%s:%d: %s was %s (%d), expected %s (%d)\n",
            file,
            line,
            actual_expression,
            pv_status_string(actual),
            (int)actual,
            pv_status_string(expected),
            (int)expected
        );
    }
}

int pv_test_failure_count(void)
{
    return failures;
}

unsigned pv_test_case_count(void)
{
    return cases_run;
}

unsigned pv_test_check_count(void)
{
    return checks_run;
}

bool pv_test_make_temp_dir(char *path, size_t path_size)
{
    static const char pattern[] = "/tmp/pvault-test-XXXXXX";

    if (path == NULL || path_size < sizeof pattern) {
        return false;
    }
    (void)memcpy(path, pattern, sizeof pattern);
    return mkdtemp(path) != NULL;
}

void pv_test_remove_temp_tree(const char *path)
{
    static const char prefix[] = "/tmp/pvault-test-";

    if (path == NULL || strncmp(path, prefix, sizeof prefix - 1U) != 0) {
        return;
    }
    remove_tree_impl(path);
}

int main(void)
{
    pv_status status;

    status = pv_global_init();
    if (status != PV_OK) {
        (void)fprintf(stderr, "pv_global_init failed: %s\n", pv_status_string(status));
        return 1;
    }

    pv_test_crypto_suite();
    pv_test_cbor_suite();
    pv_test_recovery_suite();
    pv_test_store_suite();
#ifdef PVAULT_TEST_FAULT_INJECTION
    pv_test_store_fault_suite();
#endif

    pv_global_cleanup();
    (void)fprintf(
        stderr,
        "[==========] %u cases, %u checks, %d failures\n",
        pv_test_case_count(),
        pv_test_check_count(),
        pv_test_failure_count()
    );
    return pv_test_failure_count() == 0 ? 0 : 1;
}
