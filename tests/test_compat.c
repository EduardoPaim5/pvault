#define _POSIX_C_SOURCE 200809L

#include "test.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define V1_FIXTURE_BODY_LEN 4112U
#define V1_FIXTURE_FILE_LEN (PV_FILE_HEADER_LEN + V1_FIXTURE_BODY_LEN)

static const uint8_t v1_password[] = "pvault-v1-synthetic-password";
static const char v1_vector_default_path[] =
    "tests/compat/pvault-v1-synthetic.bin";
static const char v1_recovery_text[] =
    "PV1R-40GJ4-8S44M-K2EA1-958NJ-RB9E5-WR32C-HK6GT-KCDSR-74X3P-F1X7R-ZX834-F27DG";

static bool slice_matches(const pv_slice *const slice, const uint8_t *const data, const size_t len)
{
    return slice != NULL && slice->len == len &&
        (len == 0U || (slice->data != NULL && memcmp(slice->data, data, len) == 0));
}

static bool read_v1_fixture(uint8_t **const output, size_t *const output_len)
{
    const char *path;
    struct stat info;
    uint8_t *bytes = NULL;
    size_t offset = 0U;
    int descriptor;
    bool success = false;

    *output = NULL;
    *output_len = 0U;
    path = getenv("PVAULT_V1_VECTOR_PATH");
    if (path == NULL || path[0] == '\0') {
        path = v1_vector_default_path;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0 || fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_size != (off_t)V1_FIXTURE_FILE_LEN) {
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
        return false;
    }
    bytes = malloc(V1_FIXTURE_FILE_LEN);
    if (bytes == NULL) {
        (void)close(descriptor);
        return false;
    }
    while (offset < V1_FIXTURE_FILE_LEN) {
        const ssize_t amount = read(descriptor, bytes + offset, V1_FIXTURE_FILE_LEN - offset);

        if (amount > 0) {
            offset += (size_t)amount;
            continue;
        }
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        goto cleanup;
    }
    success = close(descriptor) == 0;
    descriptor = -1;

cleanup:
    if (descriptor >= 0) {
        (void)close(descriptor);
    }
    if (!success) {
        free(bytes);
        return false;
    }
    *output = bytes;
    *output_len = V1_FIXTURE_FILE_LEN;
    return true;
}

static bool write_exact_file(
    const char *const path,
    const uint8_t *const bytes,
    const size_t length
)
{
    size_t offset = 0U;
    int descriptor;
    bool success = false;

    descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        return false;
    }
    while (offset < length) {
        const ssize_t amount = write(descriptor, bytes + offset, length - offset);

        if (amount > 0) {
            offset += (size_t)amount;
            continue;
        }
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        goto cleanup;
    }
    success = fsync(descriptor) == 0 && close(descriptor) == 0;
    descriptor = -1;

cleanup:
    if (descriptor >= 0) {
        (void)close(descriptor);
    }
    return success;
}

static bool file_matches(const char *const path, const uint8_t *const expected, const size_t length)
{
    struct stat info;
    uint8_t *actual = NULL;
    size_t offset = 0U;
    int descriptor;
    bool matches = false;

    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &info) != 0 || info.st_size != (off_t)length) {
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
        return false;
    }
    actual = malloc(length);
    if (actual == NULL) {
        (void)close(descriptor);
        return false;
    }
    while (offset < length) {
        const ssize_t amount = read(descriptor, actual + offset, length - offset);

        if (amount > 0) {
            offset += (size_t)amount;
            continue;
        }
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        goto cleanup;
    }
    matches = close(descriptor) == 0 && sodium_memcmp(actual, expected, length) == 0;
    descriptor = -1;

cleanup:
    if (descriptor >= 0) {
        (void)close(descriptor);
    }
    free(actual);
    return matches;
}

static void check_v1_payload(const pv_vault *const vault)
{
    static const uint8_t title[] = "Synthetic fixture";
    static const uint8_t username[] = "alice@example.invalid";
    static const uint8_t password[] = "\0synthetic-password\xff";
    static const uint8_t url[] = "https://example.invalid/login";
    static const uint8_t notes[] =
        "Deterministic compatibility fixture; no real secret.";
    static const uint8_t tag_a[] = "synthetic";
    static const uint8_t tag_b[] = "compat-v1";
    static const uint8_t field_a_name[] = "api-token";
    static const uint8_t field_a_value[] = "synthetic-token-\0\xff";
    static const uint8_t field_b_name[] = "account";
    static const uint8_t field_b_value[] = "fixture-0001";
    const pv_record *record;
    size_t index;

    PV_CHECK(vault->generation == 7U);
    PV_CHECK(vault->created_ms == INT64_C(1700000000123));
    PV_CHECK(vault->updated_ms == INT64_C(1700001234567));
    for (index = 0U; index < PV_DEVICE_ID_BYTES; ++index) {
        PV_CHECK(vault->device_id[index] == (uint8_t)(0xb0U + index));
    }
    PV_CHECK(vault->record_count == 1U);
    if (vault->record_count != 1U) {
        return;
    }
    record = &vault->records[0];
    for (index = 0U; index < PV_RECORD_ID_BYTES; ++index) {
        PV_CHECK(record->id[index] == (uint8_t)(0xc0U + index));
    }
    PV_CHECK(record->revision == 3U);
    PV_CHECK(record->created_ms == INT64_C(1700000100000));
    PV_CHECK(record->updated_ms == INT64_C(1700000200000));
    PV_CHECK(record->flags == PV_RECORD_FAVORITE);
    PV_CHECK(slice_matches(&record->title, title, sizeof title - 1U));
    PV_CHECK(slice_matches(&record->username, username, sizeof username - 1U));
    PV_CHECK(slice_matches(&record->password, password, sizeof password - 1U));
    PV_CHECK(slice_matches(&record->notes, notes, sizeof notes - 1U));
    PV_CHECK(record->url_count == 1U);
    if (record->url_count == 1U) {
        PV_CHECK(slice_matches(&record->urls[0], url, sizeof url - 1U));
    }
    PV_CHECK(record->tag_count == 2U);
    if (record->tag_count == 2U) {
        PV_CHECK(slice_matches(&record->tags[0], tag_a, sizeof tag_a - 1U));
        PV_CHECK(slice_matches(&record->tags[1], tag_b, sizeof tag_b - 1U));
    }
    PV_CHECK(record->field_count == 2U);
    if (record->field_count == 2U) {
        PV_CHECK(
            slice_matches(&record->fields[0].name, field_a_name, sizeof field_a_name - 1U)
        );
        PV_CHECK(
            slice_matches(&record->fields[0].value, field_a_value, sizeof field_a_value - 1U)
        );
        PV_CHECK(record->fields[0].flags == PV_FIELD_SECRET);
        PV_CHECK(
            slice_matches(&record->fields[1].name, field_b_name, sizeof field_b_name - 1U)
        );
        PV_CHECK(
            slice_matches(&record->fields[1].value, field_b_value, sizeof field_b_value - 1U)
        );
        PV_CHECK(record->fields[1].flags == 0U);
    }
}

static void compat_v1_independent_fixture_is_consumed_by_c(void)
{
    uint8_t expected_vmk[PV_WRAP_KEY_BYTES];
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    uint8_t password_vmk[PV_WRAP_KEY_BYTES] = {0};
    uint8_t recovery_vmk[PV_WRAP_KEY_BYTES] = {0};
    uint8_t decoded_recovery[PV_RECOVERY_KEY_BYTES] = {0};
    uint8_t encoded_header[PV_FILE_HEADER_LEN];
    char encoded_recovery[PV_RECOVERY_TEXT_MAX] = {0};
    uint8_t *fixture = NULL;
    size_t fixture_len = 0U;
    pv_file_header header;
    pv_buffer plaintext = {0};
    pv_buffer reencoded = {0};
    pv_vault vault;
    pv_status status;
    size_t index;

    (void)memset(&header, 0, sizeof header);
    (void)memset(&vault, 0, sizeof vault);
    PV_CHECK(read_v1_fixture(&fixture, &fixture_len));
    if (fixture == NULL) {
        return;
    }
    PV_CHECK(fixture_len == V1_FIXTURE_FILE_LEN);

    status = pv_header_decode(fixture, &header);
    PV_CHECK_STATUS(status, PV_OK);
    if (status != PV_OK) {
        goto cleanup;
    }
    PV_CHECK(header.major == 1U);
    PV_CHECK(header.minor == 0U);
    PV_CHECK(header.header_len == PV_FILE_HEADER_LEN);
    PV_CHECK(header.flags == 0U);
    PV_CHECK(header.password_slot.opslimit == PV_V1_PASSWORD_OPSLIMIT);
    PV_CHECK(header.password_slot.memlimit == PV_V1_PASSWORD_MEMLIMIT);
    PV_CHECK(header.body_ciphertext_len == V1_FIXTURE_BODY_LEN);
    for (index = 0U; index < PV_VAULT_ID_BYTES; ++index) {
        PV_CHECK(header.vault_id[index] == (uint8_t)(0x10U + index));
    }
    status = pv_header_encode(&header, encoded_header);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        PV_CHECK(memcmp(encoded_header, fixture, sizeof encoded_header) == 0);
    }

    for (index = 0U; index < PV_WRAP_KEY_BYTES; ++index) {
        expected_vmk[index] = (uint8_t)(0x40U + index);
        recovery_key[index] = (uint8_t)(0x20U + index);
    }
    status = pv_recovery_decode(v1_recovery_text, header.vault_id, decoded_recovery);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        PV_CHECK(sodium_memcmp(decoded_recovery, recovery_key, sizeof recovery_key) == 0);
    }
    status = pv_recovery_encode(
        header.vault_id,
        recovery_key,
        encoded_recovery,
        sizeof encoded_recovery
    );
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        PV_CHECK(strcmp(encoded_recovery, v1_recovery_text) == 0);
    }
    status = pv_crypto_unlock_password(
        &header,
        v1_password,
        sizeof v1_password - 1U,
        password_vmk
    );
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        PV_CHECK(sodium_memcmp(password_vmk, expected_vmk, sizeof expected_vmk) == 0);
    }
    status = pv_crypto_unlock_recovery(&header, recovery_key, recovery_vmk);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        PV_CHECK(sodium_memcmp(recovery_vmk, expected_vmk, sizeof expected_vmk) == 0);
    }
    if (sodium_memcmp(password_vmk, expected_vmk, sizeof expected_vmk) != 0) {
        goto cleanup;
    }

    status = pv_crypto_decrypt_body(
        &header,
        password_vmk,
        fixture + PV_FILE_HEADER_LEN,
        fixture_len - PV_FILE_HEADER_LEN,
        &plaintext
    );
    PV_CHECK_STATUS(status, PV_OK);
    if (status != PV_OK) {
        goto cleanup;
    }
    status = pv_model_init(&vault, "compat-v1-synthetic.bin");
    PV_CHECK_STATUS(status, PV_OK);
    if (status != PV_OK) {
        goto cleanup;
    }
    (void)memcpy(vault.vault_id, header.vault_id, sizeof vault.vault_id);
    status = pv_cbor_decode(plaintext.data, plaintext.len, &vault);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        check_v1_payload(&vault);
        status = pv_cbor_encode(&vault, &reencoded);
        PV_CHECK_STATUS(status, PV_OK);
        if (status == PV_OK) {
            PV_CHECK(reencoded.len == plaintext.len);
            if (reencoded.len == plaintext.len) {
                PV_CHECK(memcmp(reencoded.data, plaintext.data, plaintext.len) == 0);
            }
        }
    }

cleanup:
    pv_model_destroy(&vault);
    pv_buffer_secure_free(&reencoded);
    pv_buffer_secure_free(&plaintext);
    sodium_memzero(encoded_recovery, sizeof encoded_recovery);
    sodium_memzero(decoded_recovery, sizeof decoded_recovery);
    sodium_memzero(recovery_vmk, sizeof recovery_vmk);
    sodium_memzero(password_vmk, sizeof password_vmk);
    sodium_memzero(recovery_key, sizeof recovery_key);
    sodium_memzero(expected_vmk, sizeof expected_vmk);
    sodium_memzero(encoded_header, sizeof encoded_header);
    sodium_memzero(&header, sizeof header);
    free(fixture);
}

static void compat_v1_fixture_rejects_wrong_credentials_and_tampering(void)
{
    static const uint8_t wrong_password[] = "pvault-v1-synthetic-passw0rd";
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    uint8_t vmk[PV_WRAP_KEY_BYTES] = {0};
    uint8_t *fixture = NULL;
    size_t fixture_len = 0U;
    pv_file_header header;
    pv_buffer plaintext = {0};
    pv_status status;
    size_t index;

    (void)memset(&header, 0, sizeof header);
    PV_CHECK(read_v1_fixture(&fixture, &fixture_len));
    if (fixture == NULL) {
        return;
    }
    status = pv_header_decode(fixture, &header);
    PV_CHECK_STATUS(status, PV_OK);
    if (status != PV_OK) {
        goto cleanup;
    }
    status = pv_crypto_unlock_password(
        &header,
        wrong_password,
        sizeof wrong_password - 1U,
        vmk
    );
    PV_CHECK_STATUS(status, PV_ERR_AUTH);
    sodium_memzero(vmk, sizeof vmk);

    for (index = 0U; index < PV_RECOVERY_KEY_BYTES; ++index) {
        recovery_key[index] = (uint8_t)(0x20U + index);
    }
    recovery_key[0] ^= 0x01U;
    status = pv_crypto_unlock_recovery(&header, recovery_key, vmk);
    PV_CHECK_STATUS(status, PV_ERR_AUTH);
    sodium_memzero(vmk, sizeof vmk);

    status = pv_crypto_unlock_password(
        &header,
        v1_password,
        sizeof v1_password - 1U,
        vmk
    );
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        fixture[fixture_len - 1U] ^= 0x01U;
        status = pv_crypto_decrypt_body(
            &header,
            vmk,
            fixture + PV_FILE_HEADER_LEN,
            fixture_len - PV_FILE_HEADER_LEN,
            &plaintext
        );
        PV_CHECK_STATUS(status, PV_ERR_AUTH);
    }

cleanup:
    pv_buffer_secure_free(&plaintext);
    sodium_memzero(vmk, sizeof vmk);
    sodium_memzero(recovery_key, sizeof recovery_key);
    sodium_memzero(&header, sizeof header);
    free(fixture);
}

static void compat_future_minor_fails_closed_without_rewriting(void)
{
    char directory[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    char doctor_message[256] = {0};
    uint8_t *fixture = NULL;
    size_t fixture_len = 0U;
    pv_file_header header;
    pv_vault vault;
    pv_status status;
    int written;
    bool created;
    bool stored;

    (void)memset(&header, 0, sizeof header);
    (void)memset(&vault, 0, sizeof vault);
    PV_CHECK(read_v1_fixture(&fixture, &fixture_len));
    if (fixture == NULL) {
        return;
    }
    fixture[10] = (uint8_t)(PV_FILE_MINOR + 1U);
    fixture[11] = 0U;
    created = pv_test_make_temp_dir(directory, sizeof directory);
    PV_CHECK(created);
    if (!created) {
        goto cleanup;
    }
    written = snprintf(path, sizeof path, "%s/future-minor.pvlt", directory);
    PV_CHECK(written > 0 && (size_t)written < sizeof path);
    if (written <= 0 || (size_t)written >= sizeof path) {
        goto cleanup;
    }
    stored = write_exact_file(path, fixture, fixture_len);
    PV_CHECK(stored);
    if (!stored) {
        goto cleanup;
    }

    status = pv_store_open_password(
        path,
        v1_password,
        sizeof v1_password - 1U,
        &vault,
        &header
    );
    PV_CHECK_STATUS(status, PV_ERR_UNSUPPORTED);
    pv_model_destroy(&vault);

    status = pv_store_doctor(path, doctor_message, sizeof doctor_message);
    PV_CHECK_STATUS(status, PV_ERR_UNSUPPORTED);
    PV_CHECK(strstr(doctor_message, "unsupported or corrupted") != NULL);
    PV_CHECK(file_matches(path, fixture, fixture_len));

cleanup:
    pv_model_destroy(&vault);
    sodium_memzero(&header, sizeof header);
    free(fixture);
    pv_test_remove_temp_tree(directory);
}

void pv_test_compat_suite(void)
{
    pv_test_run(
        "compat.v1_independent_fixture_is_consumed_by_c",
        compat_v1_independent_fixture_is_consumed_by_c
    );
    pv_test_run(
        "compat.v1_fixture_rejects_wrong_credentials_and_tampering",
        compat_v1_fixture_rejects_wrong_credentials_and_tampering
    );
    pv_test_run(
        "compat.future_minor_fails_closed_without_rewriting",
        compat_future_minor_fails_closed_without_rewriting
    );
}
