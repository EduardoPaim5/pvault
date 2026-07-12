#include "clipboard.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void wipe_bytes(void *memory, size_t length)
{
    volatile unsigned char *cursor = memory;

    while (length > 0U) {
        *cursor++ = 0U;
        --length;
    }
}

static int read_secret(unsigned char *buffer, size_t capacity, size_t *length)
{
    size_t used = 0U;

    while (used < capacity) {
        ssize_t received = read(STDIN_FILENO, buffer + used, capacity - used);

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received < 0) {
            return -1;
        }
        if (received == 0) {
            *length = used;
            return 0;
        }
        used += (size_t)received;
    }
    errno = EOVERFLOW;
    return -1;
}

int main(int argc, char **argv)
{
    pv_clipboard_job job;
    unsigned char *secret = NULL;
    size_t secret_len = 0U;
    unsigned long ttl;
    char *end = NULL;
    pv_status status;

    if (argc != 3 || argv == NULL ||
        (strcmp(argv[1], "send") != 0 &&
         strcmp(argv[1], "cancel") != 0 &&
         strcmp(argv[1], "hold") != 0)) {
        return pv_status_exit_code(PV_ERR_USAGE);
    }
    errno = 0;
    ttl = strtoul(argv[2], &end, 10);
    if (errno != 0 || end == argv[2] || *end != '\0' || ttl == 0UL || ttl > 86400UL) {
        return pv_status_exit_code(PV_ERR_USAGE);
    }

    status = pv_clipboard_prepare(&job, (unsigned)ttl);
    if (status != PV_OK) {
        return pv_status_exit_code(status);
    }
    (void)printf("SUPERVISOR %ld\n", (long)job.supervisor_pid);
    (void)fflush(stdout);

    if (strcmp(argv[1], "cancel") == 0) {
        pv_clipboard_cancel(&job);
        return 0;
    }
    if (strcmp(argv[1], "hold") == 0) {
        for (;;) {
            (void)pause();
        }
    }

    secret = malloc(PV_MAX_PLAINTEXT);
    if (secret == NULL) {
        pv_clipboard_cancel(&job);
        return pv_status_exit_code(PV_ERR_NOMEM);
    }
    if (read_secret(secret, PV_MAX_PLAINTEXT, &secret_len) != 0 || secret_len == 0U) {
        wipe_bytes(secret, PV_MAX_PLAINTEXT);
        free(secret);
        pv_clipboard_cancel(&job);
        return pv_status_exit_code(PV_ERR_IO);
    }
    status = pv_clipboard_send(&job, secret, secret_len);
    wipe_bytes(secret, PV_MAX_PLAINTEXT);
    free(secret);
    return pv_status_exit_code(status);
}
