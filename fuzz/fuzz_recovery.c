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

static void fuzz_decode_recovery(
    const char *encoded,
    const uint8_t vault_id[PV_VAULT_ID_BYTES]
)
{
    uint8_t key[PV_RECOVERY_KEY_BYTES] = {0};

    (void)pv_recovery_decode(encoded, vault_id, key);
    sodium_memzero(key, sizeof key);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint8_t vault_id[PV_VAULT_ID_BYTES] = {
        0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
        0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 0x1dU, 0x1eU, 0x1fU
    };
    static const char valid_recovery[] =
        "PV1R-000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FZBZV-DB15G";
    char encoded[PV_RECOVERY_TEXT_MAX];
    char structured[sizeof valid_recovery];
    size_t copy_len;
    size_t index;

    if (!fuzz_initialized()) {
        return 0;
    }
    copy_len = size < sizeof encoded - 1U ? size : sizeof encoded - 1U;
    if (copy_len > 0U) {
        (void)memcpy(encoded, data, copy_len);
    }
    encoded[copy_len] = '\0';
    fuzz_decode_recovery(encoded, vault_id);

    (void)memcpy(structured, valid_recovery, sizeof structured);
    for (index = 0U; index + 1U < size; index += 2U) {
        const size_t position = (size_t)data[index] % (sizeof structured - 1U);

        structured[position] ^= (char)data[index + 1U];
    }
    fuzz_decode_recovery(structured, vault_id);
    sodium_memzero(encoded, sizeof encoded);
    sodium_memzero(structured, sizeof structured);
    return 0;
}
