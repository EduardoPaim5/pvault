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

static void fuzz_decode_header(const uint8_t input[PV_FILE_HEADER_LEN])
{
    uint8_t encoded[PV_FILE_HEADER_LEN];
    pv_file_header header;

    if (pv_header_decode(input, &header) == PV_OK) {
        (void)pv_header_encode(&header, encoded);
        sodium_memzero(&header, sizeof header);
        sodium_memzero(encoded, sizeof encoded);
    }
}

static void make_valid_header(uint8_t output[PV_FILE_HEADER_LEN])
{
    static const uint8_t magic[PV_MAGIC_LEN] = {
        'P', 'V', 'L', 'T', 0x0dU, 0x0aU, 0x1aU, 0x0aU
    };
    pv_file_header header;

    (void)memset(&header, 0, sizeof header);
    (void)memcpy(header.magic, magic, sizeof magic);
    header.major = PV_FILE_MAJOR;
    header.minor = PV_FILE_MINOR;
    header.header_len = PV_FILE_HEADER_LEN;
    header.vault_id[0] = 1U;
    header.kdf_id = PV_KDF_ARGON2ID13;
    header.wrap_aead_id = PV_AEAD_XCHACHA20POLY1305;
    header.body_aead_id = PV_AEAD_XCHACHA20POLY1305;
    header.slot_count = 2U;
    header.password_slot.opslimit = crypto_pwhash_OPSLIMIT_MIN;
    header.password_slot.memlimit = crypto_pwhash_MEMLIMIT_MIN;
    header.body_ciphertext_len = 4096U + PV_BODY_TAG_BYTES;
    (void)pv_header_encode(&header, output);
    sodium_memzero(&header, sizeof header);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t raw[PV_FILE_HEADER_LEN] = {0};
    uint8_t structured[PV_FILE_HEADER_LEN];
    size_t copy_len;
    size_t index;

    if (!fuzz_initialized()) {
        return 0;
    }
    copy_len = size < sizeof raw ? size : sizeof raw;
    if (copy_len > 0U) {
        (void)memcpy(raw, data, copy_len);
    }
    fuzz_decode_header(raw);

    make_valid_header(structured);
    for (index = 0U; index + 1U < size; index += 2U) {
        const size_t position = (size_t)data[index] % sizeof structured;

        structured[position] ^= data[index + 1U];
    }
    fuzz_decode_header(structured);
    return 0;
}
