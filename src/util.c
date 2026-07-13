#include "pvault_internal.h"

#include <ctype.h>
#include <string.h>
#include <time.h>

bool pv_utf8_valid(const uint8_t *const data, const size_t len)
{
    size_t i = 0U;

    if (data == NULL && len != 0U) {
        return false;
    }
    while (i < len) {
        const uint8_t first = data[i++];
        uint32_t codepoint;
        unsigned continuation;
        unsigned j;

        if (first <= 0x7fU) {
            continue;
        }
        if (first >= 0xc2U && first <= 0xdfU) {
            codepoint = first & 0x1fU;
            continuation = 1U;
        } else if (first >= 0xe0U && first <= 0xefU) {
            codepoint = first & 0x0fU;
            continuation = 2U;
        } else if (first >= 0xf0U && first <= 0xf4U) {
            codepoint = first & 0x07U;
            continuation = 3U;
        } else {
            return false;
        }
        if (continuation > len - i) {
            return false;
        }
        for (j = 0U; j < continuation; ++j) {
            const uint8_t next = data[i++];
            if ((next & 0xc0U) != 0x80U) {
                return false;
            }
            codepoint = (codepoint << 6U) | (next & 0x3fU);
        }
        if ((continuation == 2U && codepoint < 0x800U) ||
            (continuation == 3U && codepoint < 0x10000U) ||
            codepoint > 0x10ffffU || (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
            return false;
        }
    }
    return true;
}

static bool display_codepoint_unsafe(const uint32_t codepoint)
{
    return codepoint <= 0x1fU || (codepoint >= 0x7fU && codepoint <= 0x9fU) ||
        codepoint == 0x061cU || (codepoint >= 0x200bU && codepoint <= 0x200fU) ||
        (codepoint >= 0x2028U && codepoint <= 0x202eU) ||
        (codepoint >= 0x2060U && codepoint <= 0x2069U) || codepoint == 0xfeffU;
}

static size_t decode_codepoint(const uint8_t *const data, const size_t len, uint32_t *const codepoint)
{
    uint32_t value;
    size_t width;
    size_t i;

    if (len == 0U) return 0U;
    if (data[0] <= 0x7fU) {
        *codepoint = data[0];
        return 1U;
    }
    if (data[0] >= 0xc2U && data[0] <= 0xdfU) {
        value = data[0] & 0x1fU;
        width = 2U;
    } else if (data[0] >= 0xe0U && data[0] <= 0xefU) {
        value = data[0] & 0x0fU;
        width = 3U;
    } else if (data[0] >= 0xf0U && data[0] <= 0xf4U) {
        value = data[0] & 0x07U;
        width = 4U;
    } else {
        return 0U;
    }
    if (width > len) return 0U;
    for (i = 1U; i < width; ++i) {
        if ((data[i] & 0xc0U) != 0x80U) return 0U;
        value = (value << 6U) | (data[i] & 0x3fU);
    }
    if ((width == 3U && value < 0x800U) || (width == 4U && value < 0x10000U) ||
        value > 0x10ffffU || (value >= 0xd800U && value <= 0xdfffU)) {
        return 0U;
    }
    *codepoint = value;
    return width;
}

bool pv_text_sanitize(
    const pv_slice *const slice,
    uint8_t *const output,
    const size_t capacity,
    size_t *const output_len
)
{
    size_t input_position = 0U;
    size_t output_position = 0U;

    if (slice == NULL || output_len == NULL ||
        (slice->data == NULL && slice->len != 0U) ||
        (output == NULL && slice->len != 0U) || capacity < slice->len) {
        return false;
    }
    while (input_position < slice->len) {
        uint32_t codepoint = 0U;
        size_t width = decode_codepoint(
            slice->data + input_position,
            slice->len - input_position,
            &codepoint
        );

        if (width == 0U || display_codepoint_unsafe(codepoint)) {
            output[output_position++] = (uint8_t)'?';
            input_position += width == 0U ? 1U : width;
        } else {
            (void)memcpy(output + output_position, slice->data + input_position, width);
            output_position += width;
            input_position += width;
        }
    }
    *output_len = output_position;
    return true;
}

void pv_text_fprint(FILE *const stream, const pv_slice *const slice)
{
    size_t position = 0U;
    size_t safe_start = 0U;

    if (stream == NULL || slice == NULL || (slice->data == NULL && slice->len != 0U)) return;
    while (position < slice->len) {
        uint32_t codepoint = 0U;
        const size_t width = decode_codepoint(
            slice->data + position,
            slice->len - position,
            &codepoint
        );

        if (width == 0U || display_codepoint_unsafe(codepoint)) {
            if (position > safe_start) {
                (void)fwrite(slice->data + safe_start, 1U, position - safe_start, stream);
            }
            (void)fputc('?', stream);
            position += width == 0U ? 1U : width;
            safe_start = position;
        } else {
            position += width;
        }
    }
    if (position > safe_start) {
        (void)fwrite(slice->data + safe_start, 1U, position - safe_start, stream);
    }
}

bool pv_size_add(const size_t a, const size_t b, size_t *const out)
{
    if (out == NULL || b > SIZE_MAX - a) {
        return false;
    }
    *out = a + b;
    return true;
}

bool pv_size_mul(const size_t a, const size_t b, size_t *const out)
{
    if (out == NULL || (a != 0U && b > SIZE_MAX / a)) {
        return false;
    }
    *out = a * b;
    return true;
}

int64_t pv_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (int64_t)ts.tv_sec * INT64_C(1000) + (int64_t)(ts.tv_nsec / 1000000L);
}

void pv_hex_encode(
    const uint8_t *const input,
    const size_t input_len,
    char *const output,
    const size_t output_len
)
{
    static const char alphabet[] = "0123456789abcdef";
    size_t i;

    if (output == NULL || output_len == 0U) {
        return;
    }
    if (input == NULL || input_len > (output_len - 1U) / 2U) {
        output[0] = '\0';
        return;
    }
    for (i = 0U; i < input_len; ++i) {
        output[i * 2U] = alphabet[input[i] >> 4U];
        output[i * 2U + 1U] = alphabet[input[i] & 0x0fU];
    }
    output[input_len * 2U] = '\0';
}

static int hex_value(const char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

bool pv_hex_decode(const char *const input, uint8_t *const output, const size_t output_len)
{
    size_t i;

    if (input == NULL || output == NULL || strlen(input) != output_len * 2U) {
        return false;
    }
    for (i = 0U; i < output_len; ++i) {
        const int high = hex_value(input[i * 2U]);
        const int low = hex_value(input[i * 2U + 1U]);
        if (high < 0 || low < 0) {
            return false;
        }
        output[i] = (uint8_t)((unsigned)high << 4U) | (uint8_t)low;
    }
    return true;
}

static unsigned char ascii_fold(const unsigned char c)
{
    if (c >= (unsigned char)'A' && c <= (unsigned char)'Z') {
        return (unsigned char)(c + ((unsigned char)'a' - (unsigned char)'A'));
    }
    return c;
}

bool pv_slice_equal_cstr(const pv_slice *const slice, const char *const text, const bool ascii_casefold)
{
    size_t i;
    const size_t text_len = text == NULL ? 0U : strlen(text);

    if (slice == NULL || text == NULL || slice->len != text_len) {
        return false;
    }
    for (i = 0U; i < text_len; ++i) {
        const unsigned char left = slice->data[i];
        const unsigned char right = (unsigned char)text[i];
        if ((ascii_casefold ? ascii_fold(left) : left) !=
            (ascii_casefold ? ascii_fold(right) : right)) {
            return false;
        }
    }
    return true;
}

bool pv_slice_contains_cstr(const pv_slice *const slice, const char *const text, const bool ascii_casefold)
{
    size_t i;
    size_t j;
    const size_t needle_len = text == NULL ? 0U : strlen(text);

    if (slice == NULL || text == NULL || needle_len == 0U || needle_len > slice->len) {
        return false;
    }
    for (i = 0U; i <= slice->len - needle_len; ++i) {
        for (j = 0U; j < needle_len; ++j) {
            const unsigned char left = slice->data[i + j];
            const unsigned char right = (unsigned char)text[j];
            if ((ascii_casefold ? ascii_fold(left) : left) !=
                (ascii_casefold ? ascii_fold(right) : right)) {
                break;
            }
        }
        if (j == needle_len) {
            return true;
        }
    }
    return false;
}
