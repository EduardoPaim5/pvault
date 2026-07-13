#include "test.h"

#include <string.h>

static void text_sanitizer_replaces_terminal_controls(void)
{
    uint8_t input[] = {
        'A', 0x1bU, 'B', 0xc2U, 0x85U, 'C', 0xe2U, 0x80U, 0xaeU, 'D', 0xffU
    };
    static const uint8_t expected[] = { 'A', '?', 'B', '?', 'C', '?', 'D', '?' };
    const pv_slice slice = { input, sizeof(input) };
    uint8_t output[sizeof(input)] = { 0 };
    size_t output_len = 0U;

    PV_CHECK(pv_text_sanitize(&slice, output, sizeof(output), &output_len));
    PV_CHECK(output_len == sizeof(expected));
    PV_CHECK(memcmp(output, expected, sizeof(expected)) == 0);
}

static void text_sanitizer_preserves_valid_utf8(void)
{
    uint8_t input[] = { 'C', 'a', 'f', 0xc3U, 0xa9U };
    const pv_slice slice = { input, sizeof(input) };
    uint8_t output[sizeof(input)] = { 0 };
    size_t output_len = 0U;

    PV_CHECK(pv_text_sanitize(&slice, output, sizeof(output), &output_len));
    PV_CHECK(output_len == sizeof(input));
    PV_CHECK(memcmp(output, input, sizeof(input)) == 0);
}

static void text_sanitizer_rejects_short_output(void)
{
    uint8_t input[] = { 'a', 'b' };
    const pv_slice slice = { input, sizeof(input) };
    uint8_t output[1] = { 0 };
    size_t output_len = 99U;

    PV_CHECK(!pv_text_sanitize(&slice, output, sizeof(output), &output_len));
    PV_CHECK(output_len == 99U);
}

void pv_test_util_suite(void)
{
    pv_test_run("util.text_sanitizer_replaces_terminal_controls", text_sanitizer_replaces_terminal_controls);
    pv_test_run("util.text_sanitizer_preserves_valid_utf8", text_sanitizer_preserves_valid_utf8);
    pv_test_run("util.text_sanitizer_rejects_short_output", text_sanitizer_rejects_short_output);
}
