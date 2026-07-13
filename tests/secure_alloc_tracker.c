#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

void *__real_sodium_malloc(size_t size);
void __real_sodium_free(void *pointer);
void *__wrap_sodium_malloc(size_t size);
void __wrap_sodium_free(void *pointer);
size_t pv_test_secure_alloc_outstanding(void);

static size_t secure_alloc_outstanding;
static bool secure_alloc_underflow;
static bool secure_alloc_exit_registered;

static void secure_alloc_check_at_exit(void)
{
    static const char failure[] =
        "pvault-test: unbalanced sodium_malloc/sodium_free ownership\n";

    if (secure_alloc_outstanding != 0U || secure_alloc_underflow) {
        (void)write(STDERR_FILENO, failure, sizeof(failure) - 1U);
        _Exit(24);
    }
}

void *__wrap_sodium_malloc(const size_t size)
{
    void *const allocation = __real_sodium_malloc(size);

    if (allocation == NULL) {
        return NULL;
    }
    if (!secure_alloc_exit_registered) {
        if (atexit(secure_alloc_check_at_exit) != 0) {
            __real_sodium_free(allocation);
            return NULL;
        }
        secure_alloc_exit_registered = true;
    }
    ++secure_alloc_outstanding;
    return allocation;
}

void __wrap_sodium_free(void *const pointer)
{
    if (pointer != NULL) {
        if (secure_alloc_outstanding == 0U) {
            secure_alloc_underflow = true;
        } else {
            --secure_alloc_outstanding;
        }
    }
    __real_sodium_free(pointer);
}

size_t pv_test_secure_alloc_outstanding(void)
{
    return secure_alloc_outstanding;
}
