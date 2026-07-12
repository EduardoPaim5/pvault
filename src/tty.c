#include "cli.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

pv_status pv_tty_read_line(
    const char *const prompt,
    const size_t maximum,
    const bool allow_empty,
    pv_buffer *const output
)
{
    int fd;
    size_t used = 0U;
    bool overflow = false;

    if (prompt == NULL || output == NULL || maximum == 0U || maximum > PV_MAX_PLAINTEXT) {
        return PV_ERR_USAGE;
    }
    *output = (pv_buffer){ .secure = true };
    output->data = sodium_malloc(maximum + 1U);
    if (output->data == NULL || sodium_mlock(output->data, maximum + 1U) != 0) {
        sodium_free(output->data);
        output->data = NULL;
        return PV_ERR_SECURE_MEMORY;
    }
    fd = open("/dev/tty", O_RDWR | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        (void)fprintf(stderr, "pvault: a controlling terminal (/dev/tty) is required for interactive input\n");
        pv_buffer_secure_free(output);
        return PV_ERR_IO;
    }
    if (dprintf(fd, "%s", prompt) < 0) {
        (void)close(fd);
        pv_buffer_secure_free(output);
        return PV_ERR_IO;
    }
    for (;;) {
        uint8_t byte;
        ssize_t got;
        do {
            got = read(fd, &byte, 1U);
        } while (got < 0 && errno == EINTR);
        if (got <= 0) {
            (void)close(fd);
            pv_buffer_secure_free(output);
            return PV_ERR_IO;
        }
        if (byte == (uint8_t)'\n' || byte == (uint8_t)'\r') {
            break;
        }
        if (used < maximum) {
            output->data[used++] = byte;
        } else {
            overflow = true;
        }
    }
    (void)close(fd);
    output->data[used] = 0U;
    output->len = used;
    if (overflow) {
        pv_buffer_secure_free(output);
        return PV_ERR_LIMIT;
    }
    if (!allow_empty && used == 0U) {
        pv_buffer_secure_free(output);
        return PV_ERR_USAGE;
    }
    return PV_OK;
}

pv_status pv_tty_confirm(const char *const prompt, bool *const confirmed)
{
    pv_buffer answer = { 0 };
    pv_status status;

    if (confirmed == NULL) {
        return PV_ERR_USAGE;
    }
    *confirmed = false;
    status = pv_tty_read_line(prompt, 8U, true, &answer);
    if (status == PV_OK) {
        *confirmed = answer.len == 1U && (answer.data[0] == (uint8_t)'y' || answer.data[0] == (uint8_t)'Y');
    }
    pv_buffer_secure_free(&answer);
    return status;
}

pv_status pv_tty_read_unsigned(
    const char *const prompt,
    const unsigned maximum,
    const unsigned default_value,
    unsigned *const value
)
{
    pv_buffer answer = { 0 };
    char *end = NULL;
    unsigned long parsed;
    pv_status status;

    if (value == NULL || default_value > maximum) {
        return PV_ERR_USAGE;
    }
    status = pv_tty_read_line(prompt, 16U, true, &answer);
    if (status != PV_OK) {
        return status;
    }
    if (answer.len == 0U) {
        *value = default_value;
        pv_buffer_secure_free(&answer);
        return PV_OK;
    }
    errno = 0;
    parsed = strtoul((const char *)answer.data, &end, 10);
    if (errno != 0 || end == (char *)answer.data || *end != '\0' || parsed > maximum) {
        status = PV_ERR_USAGE;
    } else {
        *value = (unsigned)parsed;
    }
    pv_buffer_secure_free(&answer);
    return status;
}
