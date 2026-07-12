#define _POSIX_C_SOURCE 200809L

#include "pvault_internal.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static bool fuzz_initialized(void)
{
    static int state;

    if (state == 0) {
        state = sodium_init() >= 0 ? 1 : -1;
    }
    return state > 0;
}

static void fuzz_decode_cbor(const uint8_t *data, const size_t size)
{
    pv_vault vault;
    pv_buffer encoded = {0};
    pv_status status;

    if (size == 0U || size > PV_MAX_PLAINTEXT) {
        return;
    }
    (void)memset(&vault, 0, sizeof vault);
    status = pv_model_init(&vault, "fuzz.pvlt");
    if (status != PV_OK) {
        return;
    }
    status = pv_cbor_decode(data, size, &vault);
    if (status == PV_OK) {
        (void)pv_cbor_encode(&vault, &encoded);
        pv_buffer_secure_free(&encoded);
    }
    pv_model_destroy(&vault);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint8_t valid_empty_vault[] = {
        0xa6U,
        0x00U, 0x01U,
        0x01U, 0x00U,
        0x02U, 0x50U,
        0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x03U, 0x00U,
        0x04U, 0x00U,
        0x05U, 0x80U
    };
    uint8_t structured[sizeof valid_empty_vault];
    size_t index;

    if (!fuzz_initialized()) {
        return 0;
    }
    fuzz_decode_cbor(data, size);

    (void)memcpy(structured, valid_empty_vault, sizeof structured);
    for (index = 0U; index + 1U < size; index += 2U) {
        const size_t position = (size_t)data[index] % sizeof structured;

        structured[position] ^= data[index + 1U];
    }
    fuzz_decode_cbor(structured, sizeof structured);
    return 0;
}
