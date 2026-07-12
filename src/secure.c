#include "pvault_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <termios.h>
#include <unistd.h>

#define PV_SECRET_INPUT_MAX 1024U

typedef struct pv_secret_signal_guard {
    struct sigaction previous[5];
    size_t installed;
} pv_secret_signal_guard;

static const int pv_secret_signals[5] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP };
static volatile sig_atomic_t pv_secret_interrupted;

static void secret_signal_handler(const int signal_number)
{
    if (pv_secret_interrupted == 0) {
        pv_secret_interrupted = signal_number;
    }
}

static bool secret_signal_guard_install(pv_secret_signal_guard *const guard)
{
    struct sigaction action;

    memset(guard, 0, sizeof(*guard));
    memset(&action, 0, sizeof(action));
    action.sa_handler = secret_signal_handler;
    if (sigemptyset(&action.sa_mask) != 0) return false;
    pv_secret_interrupted = 0;
    while (guard->installed < sizeof(pv_secret_signals) / sizeof(pv_secret_signals[0])) {
        const size_t index = guard->installed;

        if (sigaction(pv_secret_signals[index], &action, &guard->previous[index]) != 0) {
            while (guard->installed > 0U) {
                --guard->installed;
                (void)sigaction(
                    pv_secret_signals[guard->installed],
                    &guard->previous[guard->installed],
                    NULL
                );
            }
            return false;
        }
        ++guard->installed;
    }
    return true;
}

static void secret_signal_guard_restore(pv_secret_signal_guard *const guard)
{
    while (guard->installed > 0U) {
        --guard->installed;
        (void)sigaction(
            pv_secret_signals[guard->installed],
            &guard->previous[guard->installed],
            NULL
        );
    }
}

static int tcsetattr_nointr(const int fd, const int action, const struct termios *const attributes)
{
    int result;

    do {
        result = tcsetattr(fd, action, attributes);
    } while (result != 0 && errno == EINTR);
    return result;
}

pv_status pv_secure_process_hardening(void)
{
    const struct rlimit no_core = { .rlim_cur = 0U, .rlim_max = 0U };

    if (setrlimit(RLIMIT_CORE, &no_core) != 0) {
        return PV_ERR_SECURE_MEMORY;
    }
    if (prctl(PR_SET_DUMPABLE, 0L) != 0) {
        return PV_ERR_SECURE_MEMORY;
    }
    return PV_OK;
}

pv_status pv_global_init(void)
{
    if (sodium_init() < 0) {
        return PV_ERR_STATE;
    }
    return pv_secure_process_hardening();
}

void pv_secure_stack_clear(void)
{
    sodium_stackzero(4096U);
}

void pv_global_cleanup(void)
{
    pv_secure_stack_clear();
}

static pv_status allocate_secret(pv_buffer *const secret)
{
    const pv_status status = pv_secure_buffer_alloc(secret, PV_SECRET_INPUT_MAX + 1U);

    if (status == PV_OK) secret->len = 0U;
    return status;
}

pv_status pv_secure_buffer_alloc(pv_buffer *const buffer, const size_t length)
{
    if (buffer == NULL || length == 0U || length > PV_MAX_PLAINTEXT) {
        return PV_ERR_USAGE;
    }
    *buffer = (pv_buffer){ .len = length, .secure = true };
    buffer->data = sodium_malloc(length);
    if (buffer->data == NULL) {
        return PV_ERR_NOMEM;
    }
    if (sodium_mlock(buffer->data, length) != 0) {
        sodium_free(buffer->data);
        *buffer = (pv_buffer){ 0 };
        return PV_ERR_SECURE_MEMORY;
    }
    sodium_memzero(buffer->data, length);
    return PV_OK;
}

static pv_status read_one_secret(const int fd, const char *const prompt, pv_buffer *const secret)
{
    size_t used = 0U;
    bool overflow = false;
    pv_status status;

    status = allocate_secret(secret);
    if (status != PV_OK) {
        return status;
    }
    if (dprintf(fd, "%s", prompt) < 0) {
        pv_buffer_secure_free(secret);
        return PV_ERR_IO;
    }
    for (;;) {
        struct pollfd item = { .fd = fd, .events = POLLIN, .revents = 0 };
        uint8_t byte;
        ssize_t received;
        int ready;

        if (pv_secret_interrupted != 0) {
            pv_buffer_secure_free(secret);
            return PV_ERR_IO;
        }
        do {
            ready = poll(&item, 1U, 100);
        } while (ready < 0 && errno == EINTR && pv_secret_interrupted == 0);
        if (ready < 0) {
            pv_buffer_secure_free(secret);
            return PV_ERR_IO;
        }
        if (ready == 0) continue;
        do {
            received = read(fd, &byte, 1U);
        } while (received < 0 && errno == EINTR && pv_secret_interrupted == 0);
        if (received <= 0) {
            pv_buffer_secure_free(secret);
            return PV_ERR_IO;
        }
        if (byte == (uint8_t)'\n' || byte == (uint8_t)'\r') break;
        if (used < PV_SECRET_INPUT_MAX) {
            secret->data[used++] = byte;
        } else {
            overflow = true;
        }
    }
    (void)dprintf(fd, "\n");
    if (overflow) {
        pv_buffer_secure_free(secret);
        return PV_ERR_LIMIT;
    }
    secret->len = used;
    secret->data[secret->len] = 0U;
    if (secret->len == 0U) {
        pv_buffer_secure_free(secret);
        return PV_ERR_USAGE;
    }
    return PV_OK;
}

pv_status pv_secure_read_secret(const char *const prompt, pv_buffer *const secret, const bool confirm)
{
    int fd;
    struct termios original;
    struct termios hidden;
    pv_secret_signal_guard signal_guard;
    pv_buffer second = { 0 };
    pv_status status;
    int caught_signal;

    if (prompt == NULL || secret == NULL) {
        return PV_ERR_USAGE;
    }
    secret->data = NULL;
    secret->len = 0U;
    secret->secure = false;
    fd = open("/dev/tty", O_RDWR | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        (void)fprintf(stderr, "pvault: a controlling terminal (/dev/tty) is required for secret input\n");
        return PV_ERR_IO;
    }
    if (tcgetattr(fd, &original) != 0) {
        (void)close(fd);
        return PV_ERR_IO;
    }
    if (!secret_signal_guard_install(&signal_guard)) {
        (void)close(fd);
        return PV_ERR_IO;
    }
    hidden = original;
    hidden.c_lflag &= (tcflag_t)~ECHO;
    if (tcsetattr_nointr(fd, TCSAFLUSH, &hidden) != 0) {
        secret_signal_guard_restore(&signal_guard);
        (void)close(fd);
        return PV_ERR_IO;
    }
    status = read_one_secret(fd, prompt, secret);
    if (status == PV_OK && confirm) {
        status = read_one_secret(fd, "Confirm: ", &second);
        if (status == PV_OK &&
            (second.len != secret->len || sodium_memcmp(second.data, secret->data, secret->len) != 0)) {
            status = PV_ERR_AUTH;
        }
    }
    if (tcsetattr_nointr(fd, TCSAFLUSH, &original) != 0 && status == PV_OK) {
        status = PV_ERR_IO;
    }
    (void)close(fd);
    pv_buffer_secure_free(&second);
    caught_signal = (int)pv_secret_interrupted;
    secret_signal_guard_restore(&signal_guard);
    pv_secret_interrupted = 0;
    if (status != PV_OK) {
        pv_buffer_secure_free(secret);
    }
    if (caught_signal != 0) {
        pv_buffer_secure_free(secret);
        (void)raise(caught_signal);
        return PV_ERR_IO;
    }
    return status;
}

void pv_buffer_secure_free(pv_buffer *const buffer)
{
    if (buffer == NULL) {
        return;
    }
    if (buffer->data != NULL) {
        if (buffer->secure) {
            sodium_free(buffer->data);
        } else {
            free(buffer->data);
        }
    }
    buffer->data = NULL;
    buffer->len = 0U;
    buffer->secure = false;
}
