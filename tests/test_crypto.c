#define _POSIX_C_SOURCE 200809L

#include "test.h"

#include <string.h>

static const uint8_t fixture_password[] = {
    'c', 'o', 'r', 'r', 'e', 'c', 't', '-', 'h', 'o', 'r', 's', 'e'
};
static const uint8_t fixture_wrong_password[] = {
    'i', 'n', 'c', 'o', 'r', 'r', 'e', 'c', 't'
};
static uint8_t fixture_recovery[PV_RECOVERY_KEY_BYTES];
static uint8_t fixture_vmk[PV_WRAP_KEY_BYTES];
static pv_file_header fixture_header;
static bool fixture_ready;

static void crypto_fixture_setup(void)
{
    size_t index;
    pv_status status;

    (void)memset(&fixture_header, 0, sizeof fixture_header);
    for (index = 0U; index < sizeof fixture_header.vault_id; ++index) {
        fixture_header.vault_id[index] = (uint8_t)(0x10U + index);
    }
    for (index = 0U; index < sizeof fixture_recovery; ++index) {
        fixture_recovery[index] = (uint8_t)(0xa0U + index);
        fixture_vmk[index] = (uint8_t)(0x40U + index);
    }

    status = pv_crypto_create_header(
        &fixture_header,
        fixture_password,
        sizeof fixture_password,
        fixture_recovery,
        fixture_vmk
    );
    PV_CHECK(status == PV_OK);
    if (status != PV_OK) {
        return;
    }
    PV_CHECK(fixture_header.major == PV_FILE_MAJOR);
    PV_CHECK(fixture_header.minor == PV_FILE_MINOR);
    PV_CHECK(fixture_header.header_len == PV_FILE_HEADER_LEN);
    PV_CHECK(fixture_header.kdf_id == PV_KDF_ARGON2ID13);
    PV_CHECK(fixture_header.wrap_aead_id == PV_AEAD_XCHACHA20POLY1305);
    PV_CHECK(fixture_header.body_aead_id == PV_AEAD_XCHACHA20POLY1305);
    PV_CHECK(fixture_header.password_slot.opslimit == PV_V1_PASSWORD_OPSLIMIT);
    PV_CHECK(fixture_header.password_slot.memlimit == PV_V1_PASSWORD_MEMLIMIT);
    fixture_ready = true;
}

static void crypto_unlocks_keyslots_and_rejects_bad_credentials(void)
{
    pv_file_header tampered;
    uint8_t wrong_recovery[PV_RECOVERY_KEY_BYTES];
    uint8_t unlocked[PV_WRAP_KEY_BYTES] = {0};
    pv_status status;

    PV_CHECK(fixture_ready);
    if (!fixture_ready) {
        return;
    }

    status = pv_crypto_unlock_password(
        &fixture_header,
        fixture_password,
        sizeof fixture_password,
        unlocked
    );
    PV_CHECK(status == PV_OK);
    PV_CHECK(sodium_memcmp(unlocked, fixture_vmk, sizeof unlocked) == 0);
    sodium_memzero(unlocked, sizeof unlocked);

    status = pv_crypto_unlock_password(
        &fixture_header,
        fixture_wrong_password,
        sizeof fixture_wrong_password,
        unlocked
    );
    PV_CHECK(status == PV_ERR_AUTH);
    sodium_memzero(unlocked, sizeof unlocked);

    status = pv_crypto_unlock_recovery(&fixture_header, fixture_recovery, unlocked);
    PV_CHECK(status == PV_OK);
    PV_CHECK(sodium_memcmp(unlocked, fixture_vmk, sizeof unlocked) == 0);
    sodium_memzero(unlocked, sizeof unlocked);

    (void)memcpy(wrong_recovery, fixture_recovery, sizeof wrong_recovery);
    wrong_recovery[0] ^= 0x01U;
    status = pv_crypto_unlock_recovery(&fixture_header, wrong_recovery, unlocked);
    PV_CHECK(status == PV_ERR_AUTH);
    sodium_memzero(wrong_recovery, sizeof wrong_recovery);
    sodium_memzero(unlocked, sizeof unlocked);

    tampered = fixture_header;
    tampered.password_slot.wrapped_vmk[0] ^= 0x80U;
    status = pv_crypto_unlock_password(
        &tampered,
        fixture_password,
        sizeof fixture_password,
        unlocked
    );
    PV_CHECK(status == PV_ERR_AUTH);
    sodium_memzero(unlocked, sizeof unlocked);

    tampered = fixture_header;
    tampered.recovery_slot.wrapped_vmk[0] ^= 0x80U;
    status = pv_crypto_unlock_recovery(&tampered, fixture_recovery, unlocked);
    PV_CHECK(status == PV_ERR_AUTH);
    sodium_memzero(unlocked, sizeof unlocked);
}

static void crypto_body_roundtrip_authenticates_ciphertext_and_aad(void)
{
    static const uint8_t plaintext[] = {
        0x00U, 0x01U, 0x02U, 0x7fU, 0x80U, 0xfeU, 0xffU,
        'p', 'v', 'a', 'u', 'l', 't'
    };
    pv_file_header header;
    pv_file_header changed_header;
    pv_buffer ciphertext = {0};
    pv_buffer decrypted = {0};
    pv_status status;

    PV_CHECK(fixture_ready);
    if (!fixture_ready) {
        return;
    }
    header = fixture_header;

    status = pv_crypto_encrypt_body(
        &header,
        fixture_vmk,
        plaintext,
        sizeof plaintext,
        &ciphertext
    );
    PV_CHECK(status == PV_OK);
    if (status != PV_OK) {
        return;
    }
    PV_CHECK(ciphertext.data != NULL);
    PV_CHECK(ciphertext.len == 4096U + PV_BODY_TAG_BYTES);
    PV_CHECK(header.body_ciphertext_len == ciphertext.len);
    if (ciphertext.data == NULL || ciphertext.len == 0U) {
        pv_buffer_secure_free(&ciphertext);
        return;
    }

    status = pv_crypto_decrypt_body(
        &header,
        fixture_vmk,
        ciphertext.data,
        ciphertext.len,
        &decrypted
    );
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        PV_CHECK(decrypted.len == sizeof plaintext);
        PV_CHECK(sodium_memcmp(decrypted.data, plaintext, sizeof plaintext) == 0);
    }
    pv_buffer_secure_free(&decrypted);

    ciphertext.data[ciphertext.len - 1U] ^= 0x01U;
    status = pv_crypto_decrypt_body(
        &header,
        fixture_vmk,
        ciphertext.data,
        ciphertext.len,
        &decrypted
    );
    PV_CHECK(status == PV_ERR_AUTH);
    pv_buffer_secure_free(&decrypted);
    ciphertext.data[ciphertext.len - 1U] ^= 0x01U;

    changed_header = header;
    changed_header.vault_id[0] ^= 0x01U;
    status = pv_crypto_decrypt_body(
        &changed_header,
        fixture_vmk,
        ciphertext.data,
        ciphertext.len,
        &decrypted
    );
    PV_CHECK(status == PV_ERR_AUTH);
    pv_buffer_secure_free(&decrypted);

    pv_buffer_secure_free(&ciphertext);
}

static void crypto_rewrap_changes_only_selected_keyslot(void)
{
    static const uint8_t new_password[] = {
        'n', 'e', 'w', '-', 'm', 'a', 's', 't', 'e', 'r', '-', 'p', 'a', 's', 's'
    };
    uint8_t new_recovery[PV_RECOVERY_KEY_BYTES];
    pv_file_header header;
    uint8_t unlocked[PV_WRAP_KEY_BYTES] = {0};
    uint8_t original_recovery_slot[sizeof header.recovery_slot];
    uint8_t rewrapped_password_slot[sizeof header.password_slot];
    pv_status status;
    size_t index;

    PV_CHECK(fixture_ready);
    if (!fixture_ready) {
        return;
    }
    header = fixture_header;
    (void)memcpy(original_recovery_slot, &header.recovery_slot, sizeof original_recovery_slot);

    status = pv_crypto_rewrap_password(
        &header,
        new_password,
        sizeof new_password,
        fixture_vmk
    );
    PV_CHECK(status == PV_OK);
    PV_CHECK(memcmp(original_recovery_slot, &header.recovery_slot, sizeof original_recovery_slot) == 0);

    status = pv_crypto_unlock_password(
        &header,
        fixture_password,
        sizeof fixture_password,
        unlocked
    );
    PV_CHECK(status == PV_ERR_AUTH);
    sodium_memzero(unlocked, sizeof unlocked);

    status = pv_crypto_unlock_password(&header, new_password, sizeof new_password, unlocked);
    PV_CHECK(status == PV_OK);
    PV_CHECK(sodium_memcmp(unlocked, fixture_vmk, sizeof unlocked) == 0);
    sodium_memzero(unlocked, sizeof unlocked);

    status = pv_crypto_unlock_recovery(&header, fixture_recovery, unlocked);
    PV_CHECK(status == PV_OK);
    PV_CHECK(sodium_memcmp(unlocked, fixture_vmk, sizeof unlocked) == 0);
    sodium_memzero(unlocked, sizeof unlocked);

    for (index = 0U; index < sizeof new_recovery; ++index) {
        new_recovery[index] = (uint8_t)(0x20U + index);
    }
    (void)memcpy(rewrapped_password_slot, &header.password_slot, sizeof rewrapped_password_slot);
    status = pv_crypto_rewrap_recovery(&header, new_recovery, fixture_vmk);
    PV_CHECK(status == PV_OK);
    PV_CHECK(
        memcmp(rewrapped_password_slot, &header.password_slot, sizeof rewrapped_password_slot) == 0
    );
    status = pv_crypto_unlock_recovery(&header, fixture_recovery, unlocked);
    PV_CHECK(status == PV_ERR_AUTH);
    sodium_memzero(unlocked, sizeof unlocked);
    status = pv_crypto_unlock_recovery(&header, new_recovery, unlocked);
    PV_CHECK(status == PV_OK);
    PV_CHECK(sodium_memcmp(unlocked, fixture_vmk, sizeof unlocked) == 0);
    sodium_memzero(new_recovery, sizeof new_recovery);
    sodium_memzero(unlocked, sizeof unlocked);
}

static void crypto_rejects_lengths_before_accessing_input(void)
{
    uint8_t one_byte = 0U;
    pv_file_header header;
    pv_buffer output = {0};
    pv_status status;

    PV_CHECK(fixture_ready);
    if (!fixture_ready) {
        return;
    }
    header = fixture_header;
    status = pv_crypto_encrypt_body(
        &header,
        fixture_vmk,
        &one_byte,
        PV_MAX_PLAINTEXT,
        &output
    );
    PV_CHECK(status == PV_ERR_LIMIT);
    PV_CHECK(output.data == NULL);
    PV_CHECK(output.len == 0U);

    status = pv_crypto_encrypt_body(&header, fixture_vmk, &one_byte, 0U, &output);
    PV_CHECK(status == PV_ERR_USAGE);
    pv_buffer_secure_free(&output);
}

static void header_codec_roundtrips_and_rejects_invalid_preamble(void)
{
    uint8_t encoded[PV_FILE_HEADER_LEN];
    uint8_t invalid[PV_FILE_HEADER_LEN];
    pv_file_header header;
    pv_file_header decoded;
    pv_status status;

    PV_CHECK(fixture_ready);
    if (!fixture_ready) {
        return;
    }

    header = fixture_header;
    header.body_ciphertext_len = 4096U + PV_BODY_TAG_BYTES;
    status = pv_header_encode(&header, encoded);
    PV_CHECK(status == PV_OK);
    if (status != PV_OK) {
        return;
    }
    (void)memset(&decoded, 0, sizeof decoded);
    status = pv_header_decode(encoded, &decoded);
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        PV_CHECK(decoded.major == header.major);
        PV_CHECK(decoded.minor == header.minor);
        PV_CHECK(decoded.header_len == header.header_len);
        PV_CHECK(decoded.password_slot.opslimit == header.password_slot.opslimit);
        PV_CHECK(decoded.password_slot.memlimit == header.password_slot.memlimit);
        PV_CHECK(decoded.body_ciphertext_len == header.body_ciphertext_len);
        PV_CHECK(memcmp(decoded.vault_id, header.vault_id, PV_VAULT_ID_BYTES) == 0);
        PV_CHECK(
            memcmp(
                decoded.password_slot.wrapped_vmk,
                header.password_slot.wrapped_vmk,
                PV_WRAPPED_VMK_BYTES
            ) == 0
        );
    }

    (void)memcpy(invalid, encoded, sizeof invalid);
    (void)memset(invalid + 244U, 0, 8U);
    invalid[244U] = (uint8_t)PV_BODY_TAG_BYTES;
    status = pv_header_decode(invalid, &decoded);
    PV_CHECK(status == PV_ERR_FORMAT);

    header.body_ciphertext_len = 4097U + PV_BODY_TAG_BYTES;
    status = pv_header_encode(&header, invalid);
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        status = pv_header_decode(invalid, &decoded);
        PV_CHECK(status == PV_ERR_FORMAT);
    }

    (void)memcpy(invalid, encoded, sizeof invalid);
    invalid[0] ^= 0xffU;
    status = pv_header_decode(invalid, &decoded);
    PV_CHECK(status == PV_ERR_FORMAT);

    (void)memcpy(invalid, encoded, sizeof invalid);
    invalid[8] = (uint8_t)(PV_FILE_MAJOR + 1U);
    invalid[9] = 0U;
    status = pv_header_decode(invalid, &decoded);
    PV_CHECK(status == PV_ERR_UNSUPPORTED);

    (void)memcpy(invalid, encoded, sizeof invalid);
    invalid[10] = (uint8_t)(PV_FILE_MINOR + 1U);
    invalid[11] = 0U;
    status = pv_header_decode(invalid, &decoded);
    PV_CHECK(status == PV_ERR_UNSUPPORTED);

    (void)memcpy(invalid, encoded, sizeof invalid);
    (void)memset(invalid + 52U, 0xff, 8U);
    status = pv_header_decode(invalid, &decoded);
    PV_CHECK(status == PV_ERR_FORMAT);
}

static void status_mapping_distinguishes_unsupported_format(void)
{
    PV_CHECK(
        strcmp(
            pv_status_string(PV_ERR_UNSUPPORTED),
            "unsupported or corrupted vault format version"
        ) == 0
    );
    PV_CHECK(pv_status_exit_code(PV_ERR_UNSUPPORTED) == 3);
}

static pv_status header_status_with_kdf_costs(const uint64_t opslimit, const uint64_t memlimit)
{
    uint8_t encoded[PV_FILE_HEADER_LEN];
    pv_file_header header;
    pv_file_header decoded;
    pv_status status;

    header = fixture_header;
    header.body_ciphertext_len = 4096U + PV_BODY_TAG_BYTES;
    header.password_slot.opslimit = opslimit;
    header.password_slot.memlimit = memlimit;
    status = pv_header_encode(&header, encoded);
    if (status == PV_OK) {
        status = pv_header_decode(encoded, &decoded);
    }
    sodium_memzero(&decoded, sizeof decoded);
    sodium_memzero(&header, sizeof header);
    sodium_memzero(encoded, sizeof encoded);
    return status;
}

static void header_kdf_numeric_boundaries_are_explicit(void)
{
    PV_CHECK_STATUS(
        header_status_with_kdf_costs(
            PV_V1_PASSWORD_OPSLIMIT_MIN,
            PV_V1_PASSWORD_MEMLIMIT_MIN
        ),
        PV_OK
    );
    PV_CHECK_STATUS(
        header_status_with_kdf_costs(
            PV_V1_PASSWORD_OPSLIMIT_MAX,
            PV_V1_PASSWORD_MEMLIMIT_MAX
        ),
        PV_OK
    );
    PV_CHECK_STATUS(
        header_status_with_kdf_costs(
            PV_V1_PASSWORD_OPSLIMIT_MIN - 1U,
            PV_V1_PASSWORD_MEMLIMIT_MIN
        ),
        PV_ERR_FORMAT
    );
    PV_CHECK_STATUS(
        header_status_with_kdf_costs(
            PV_V1_PASSWORD_OPSLIMIT_MAX + 1U,
            PV_V1_PASSWORD_MEMLIMIT_MIN
        ),
        PV_ERR_FORMAT
    );
    PV_CHECK_STATUS(
        header_status_with_kdf_costs(
            PV_V1_PASSWORD_OPSLIMIT_MIN,
            PV_V1_PASSWORD_MEMLIMIT_MIN - 1U
        ),
        PV_ERR_FORMAT
    );
    PV_CHECK_STATUS(
        header_status_with_kdf_costs(
            PV_V1_PASSWORD_OPSLIMIT_MIN,
            PV_V1_PASSWORD_MEMLIMIT_MAX + 1U
        ),
        PV_ERR_FORMAT
    );
}

void pv_test_crypto_suite(void)
{
    pv_test_run("crypto.fixture_setup", crypto_fixture_setup);
    pv_test_run(
        "crypto.unlocks_keyslots_and_rejects_bad_credentials",
        crypto_unlocks_keyslots_and_rejects_bad_credentials
    );
    pv_test_run(
        "crypto.body_roundtrip_authenticates_ciphertext_and_aad",
        crypto_body_roundtrip_authenticates_ciphertext_and_aad
    );
    pv_test_run("crypto.rewrap_changes_only_selected_keyslot", crypto_rewrap_changes_only_selected_keyslot);
    pv_test_run(
        "crypto.rejects_lengths_before_accessing_input",
        crypto_rejects_lengths_before_accessing_input
    );
    pv_test_run(
        "header.codec_roundtrips_and_rejects_invalid_preamble",
        header_codec_roundtrips_and_rejects_invalid_preamble
    );
    pv_test_run(
        "status.mapping_distinguishes_unsupported_format",
        status_mapping_distinguishes_unsupported_format
    );
    pv_test_run(
        "header.kdf_numeric_boundaries_are_explicit",
        header_kdf_numeric_boundaries_are_explicit
    );

    sodium_memzero(fixture_recovery, sizeof fixture_recovery);
    sodium_memzero(fixture_vmk, sizeof fixture_vmk);
    sodium_memzero(&fixture_header, sizeof fixture_header);
    fixture_ready = false;
}
