#ifndef PVAULT_TEST_H
#define PVAULT_TEST_H

#include "pvault_internal.h"

#include <stdbool.h>
#include <stddef.h>

typedef void (*pv_test_function)(void);

void pv_test_run(const char *name, pv_test_function function);
void pv_test_check(bool condition, const char *expression, const char *file, int line);
void pv_test_check_status(
    pv_status actual,
    pv_status expected,
    const char *actual_expression,
    const char *file,
    int line
);
int pv_test_failure_count(void);
unsigned pv_test_case_count(void);
unsigned pv_test_check_count(void);

bool pv_test_make_temp_dir(char *path, size_t path_size);
void pv_test_remove_temp_tree(const char *path);

void pv_test_crypto_suite(void);
void pv_test_cbor_suite(void);
void pv_test_compat_suite(void);
void pv_test_recovery_suite(void);
void pv_test_store_suite(void);
#ifdef PVAULT_TEST_FAULT_INJECTION
void pv_test_store_fault_suite(void);
#endif

#define PV_CHECK(expression)                                                        \
    pv_test_check((expression), #expression, __FILE__, __LINE__)

#define PV_CHECK_STATUS(actual, expected)                                           \
    pv_test_check_status((actual), (expected), #actual, __FILE__, __LINE__)

#endif
