#define _POSIX_C_SOURCE 200809L

#include "test.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static void recovery_roundtrip_accepts_normalized_human_input(void)
{
    uint8_t vault_id[PV_VAULT_ID_BYTES];
    uint8_t generated_key[PV_RECOVERY_KEY_BYTES] = {0};
    uint8_t decoded_key[PV_RECOVERY_KEY_BYTES] = {0};
    char encoded[PV_RECOVERY_TEXT_MAX];
    char normalized[PV_RECOVERY_TEXT_MAX];
    pv_status status;
    size_t index;

    for (index = 0U; index < sizeof vault_id; ++index) {
        vault_id[index] = (uint8_t)(0x20U + index);
    }
    status = pv_recovery_generate(
        vault_id,
        generated_key,
        encoded,
        sizeof encoded
    );
    PV_CHECK(status == PV_OK);
    if (status != PV_OK) {
        return;
    }
    PV_CHECK(strncmp(encoded, "PV1R-", 5U) == 0);

    status = pv_recovery_decode(encoded, vault_id, decoded_key);
    PV_CHECK(status == PV_OK);
    PV_CHECK(sodium_memcmp(generated_key, decoded_key, sizeof generated_key) == 0);
    sodium_memzero(decoded_key, sizeof decoded_key);

    for (index = 0U; encoded[index] != '\0' && index + 1U < sizeof normalized; ++index) {
        const unsigned char character = (unsigned char)encoded[index];

        normalized[index] = character == (unsigned char)'-'
            ? ' '
            : (char)tolower(character);
    }
    normalized[index] = '\0';
    status = pv_recovery_decode(normalized, vault_id, decoded_key);
    PV_CHECK(status == PV_OK);
    PV_CHECK(sodium_memcmp(generated_key, decoded_key, sizeof generated_key) == 0);

    sodium_memzero(decoded_key, sizeof decoded_key);
    sodium_memzero(generated_key, sizeof generated_key);
    sodium_memzero(encoded, sizeof encoded);
    sodium_memzero(normalized, sizeof normalized);
}

static void recovery_rejects_corruption_wrong_vault_and_short_input(void)
{
    uint8_t vault_id[PV_VAULT_ID_BYTES];
    uint8_t wrong_vault_id[PV_VAULT_ID_BYTES];
    uint8_t generated_key[PV_RECOVERY_KEY_BYTES] = {0};
    uint8_t decoded_key[PV_RECOVERY_KEY_BYTES] = {0};
    char encoded[PV_RECOVERY_TEXT_MAX];
    char corrupted[PV_RECOVERY_TEXT_MAX];
    pv_status status;
    size_t index;

    for (index = 0U; index < sizeof vault_id; ++index) {
        vault_id[index] = (uint8_t)(0x60U + index);
    }
    (void)memcpy(wrong_vault_id, vault_id, sizeof wrong_vault_id);
    wrong_vault_id[0] ^= 0x80U;

    status = pv_recovery_generate(vault_id, generated_key, encoded, sizeof encoded);
    PV_CHECK(status == PV_OK);
    if (status != PV_OK) {
        return;
    }

    status = pv_recovery_decode(encoded, wrong_vault_id, decoded_key);
    PV_CHECK(status == PV_ERR_AUTH);
    PV_CHECK(sodium_is_zero(decoded_key, sizeof decoded_key) == 1);

    (void)memcpy(corrupted, encoded, strlen(encoded) + 1U);
    index = strlen(corrupted);
    while (index > 5U) {
        --index;
        if (isalnum((unsigned char)corrupted[index]) != 0) {
            corrupted[index] = corrupted[index] == 'A' ? 'B' : 'A';
            break;
        }
    }
    status = pv_recovery_decode(corrupted, vault_id, decoded_key);
    PV_CHECK(status == PV_ERR_AUTH);
    PV_CHECK(sodium_is_zero(decoded_key, sizeof decoded_key) == 1);

    status = pv_recovery_decode("PV1R-A", vault_id, decoded_key);
    PV_CHECK(status == PV_ERR_AUTH);

    sodium_memzero(decoded_key, sizeof decoded_key);
    sodium_memzero(generated_key, sizeof generated_key);
    sodium_memzero(encoded, sizeof encoded);
    sodium_memzero(corrupted, sizeof corrupted);
}

static void recovery_known_vector_decodes(void)
{
    static const char vector[] =
        "PV1R-000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FZBZV-DB15G";
    uint8_t vault_id[PV_VAULT_ID_BYTES];
    uint8_t expected_key[PV_RECOVERY_KEY_BYTES];
    uint8_t decoded_key[PV_RECOVERY_KEY_BYTES] = {0};
    pv_status status;
    size_t index;

    for (index = 0U; index < sizeof vault_id; ++index) {
        vault_id[index] = (uint8_t)(0x10U + index);
    }
    for (index = 0U; index < sizeof expected_key; ++index) {
        expected_key[index] = (uint8_t)index;
    }
    status = pv_recovery_decode(vector, vault_id, decoded_key);
    PV_CHECK(status == PV_OK);
    PV_CHECK(sodium_memcmp(decoded_key, expected_key, sizeof expected_key) == 0);

    sodium_memzero(expected_key, sizeof expected_key);
    sodium_memzero(decoded_key, sizeof decoded_key);
}

static void recovery_file_is_exclusive_private_and_readable(void)
{
    uint8_t vault_id[PV_VAULT_ID_BYTES];
    uint8_t generated_key[PV_RECOVERY_KEY_BYTES] = {0};
    uint8_t decoded_key[PV_RECOVERY_KEY_BYTES] = {0};
    char encoded[PV_RECOVERY_TEXT_MAX];
    char read_back[PV_RECOVERY_TEXT_MAX];
    char directory[PATH_MAX];
    char path[PATH_MAX];
    struct stat info;
    pv_status status;
    size_t index;
    int written;

    (void)memset(directory, 0, sizeof directory);
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        return;
    }
    written = snprintf(path, sizeof path, "%s/recovery.txt", directory);
    PV_CHECK(written > 0 && (size_t)written < sizeof path);
    if (written <= 0 || (size_t)written >= sizeof path) {
        pv_test_remove_temp_tree(directory);
        return;
    }
    for (index = 0U; index < sizeof vault_id; ++index) {
        vault_id[index] = (uint8_t)(0xb0U + index);
    }

    status = pv_recovery_generate(vault_id, generated_key, encoded, sizeof encoded);
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        status = pv_recovery_write_file(path, encoded, vault_id);
        PV_CHECK(status == PV_OK);
    }
    if (status == PV_OK) {
        PV_CHECK(stat(path, &info) == 0);
        if (stat(path, &info) == 0) {
            PV_CHECK((info.st_mode & 0777U) == 0600U);
            PV_CHECK(S_ISREG(info.st_mode));
        }
        status = pv_recovery_read_file(path, read_back, sizeof read_back);
        PV_CHECK(status == PV_OK);
        if (status == PV_OK) {
            status = pv_recovery_decode(read_back, vault_id, decoded_key);
            PV_CHECK(status == PV_OK);
            PV_CHECK(sodium_memcmp(decoded_key, generated_key, sizeof decoded_key) == 0);
        }
        status = pv_recovery_write_file(path, encoded, vault_id);
        PV_CHECK(status == PV_ERR_EXISTS);
    }

    sodium_memzero(decoded_key, sizeof decoded_key);
    sodium_memzero(generated_key, sizeof generated_key);
    sodium_memzero(encoded, sizeof encoded);
    sodium_memzero(read_back, sizeof read_back);
    pv_test_remove_temp_tree(directory);
}

void pv_test_recovery_suite(void)
{
    pv_test_run(
        "recovery.roundtrip_accepts_normalized_human_input",
        recovery_roundtrip_accepts_normalized_human_input
    );
    pv_test_run(
        "recovery.rejects_corruption_wrong_vault_and_short_input",
        recovery_rejects_corruption_wrong_vault_and_short_input
    );
    pv_test_run("recovery.known_vector_decodes", recovery_known_vector_decodes);
    pv_test_run(
        "recovery.file_is_exclusive_private_and_readable",
        recovery_file_is_exclusive_private_and_readable
    );
}
