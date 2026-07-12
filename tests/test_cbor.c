#define _POSIX_C_SOURCE 200809L

#include "test.h"

#include <stdlib.h>
#include <string.h>

static bool slice_matches(const pv_slice *slice, const uint8_t *expected, size_t expected_len)
{
    if (slice->len != expected_len) {
        return false;
    }
    return expected_len == 0U || memcmp(slice->data, expected, expected_len) == 0;
}

static uint8_t *find_bytes(uint8_t *haystack, size_t haystack_len, const uint8_t *needle, size_t needle_len)
{
    size_t index;

    if (needle_len == 0U || needle_len > haystack_len) {
        return NULL;
    }
    for (index = 0U; index <= haystack_len - needle_len; ++index) {
        if (memcmp(haystack + index, needle, needle_len) == 0) {
            return haystack + index;
        }
    }
    return NULL;
}

static pv_status sample_vault_init(pv_vault *vault)
{
    uint8_t title[] = "Example account";
    uint8_t username[] = "alice@example.test";
    uint8_t password[] = {0x00U, 'p', 'a', 's', 's', 0xffU};
    uint8_t notes[] = "binary-safe sample";
    uint8_t url_a[] = "https://example.test/login";
    uint8_t url_b[] = "https://accounts.example.test";
    uint8_t tag_a[] = "personal";
    uint8_t tag_b[] = "email";
    uint8_t field_name_a[] = "account-number";
    uint8_t field_value_a[] = "123456";
    uint8_t field_name_b[] = "pin";
    uint8_t field_value_b[] = {0x01U, 0x02U, 0x00U, 0xfeU};
    pv_slice urls[2];
    pv_slice tags[2];
    pv_custom_field fields[2];
    pv_record source;
    pv_record *added = NULL;
    pv_status status;
    size_t index;

    (void)memset(vault, 0, sizeof *vault);
    status = pv_model_init(vault, "test.pvlt");
    if (status != PV_OK) {
        return status;
    }

    for (index = 0U; index < sizeof vault->vault_id; ++index) {
        vault->vault_id[index] = (uint8_t)(index + 1U);
        vault->device_id[index] = (uint8_t)(0xf0U - index);
    }
    vault->generation = 23U;
    vault->created_ms = INT64_C(1700000000123);
    vault->updated_ms = INT64_C(1700001000456);

    urls[0].data = url_a;
    urls[0].len = sizeof url_a - 1U;
    urls[1].data = url_b;
    urls[1].len = sizeof url_b - 1U;
    tags[0].data = tag_a;
    tags[0].len = sizeof tag_a - 1U;
    tags[1].data = tag_b;
    tags[1].len = sizeof tag_b - 1U;

    fields[0].name.data = field_name_a;
    fields[0].name.len = sizeof field_name_a - 1U;
    fields[0].value.data = field_value_a;
    fields[0].value.len = sizeof field_value_a - 1U;
    fields[0].flags = 0U;
    fields[1].name.data = field_name_b;
    fields[1].name.len = sizeof field_name_b - 1U;
    fields[1].value.data = field_value_b;
    fields[1].value.len = sizeof field_value_b;
    fields[1].flags = PV_FIELD_SECRET;

    (void)memset(&source, 0, sizeof source);
    for (index = 0U; index < sizeof source.id; ++index) {
        source.id[index] = (uint8_t)(0x80U + index);
    }
    source.revision = 7U;
    source.created_ms = INT64_C(1700000001000);
    source.updated_ms = INT64_C(1700000002000);
    source.flags = PV_RECORD_FAVORITE;
    source.title.data = title;
    source.title.len = sizeof title - 1U;
    source.username.data = username;
    source.username.len = sizeof username - 1U;
    source.password.data = password;
    source.password.len = sizeof password;
    source.notes.data = notes;
    source.notes.len = sizeof notes - 1U;
    source.urls = urls;
    source.url_count = 2U;
    source.tags = tags;
    source.tag_count = 2U;
    source.fields = fields;
    source.field_count = 2U;

    status = pv_model_add_record(vault, &source, &added);
    if (status != PV_OK) {
        return status;
    }
    return added == NULL ? PV_ERR_STATE : PV_OK;
}

static void cbor_roundtrip_preserves_all_fields(void)
{
    static const uint8_t expected_title[] = "Example account";
    static const uint8_t expected_username[] = "alice@example.test";
    static const uint8_t expected_password[] = {0x00U, 'p', 'a', 's', 's', 0xffU};
    static const uint8_t expected_secret_value[] = {0x01U, 0x02U, 0x00U, 0xfeU};
    pv_vault source;
    pv_vault decoded;
    pv_buffer encoded = {0};
    pv_status status;

    (void)memset(&source, 0, sizeof source);
    (void)memset(&decoded, 0, sizeof decoded);
    status = sample_vault_init(&source);
    PV_CHECK(status == PV_OK);
    if (status != PV_OK) {
        pv_model_destroy(&source);
        return;
    }
    status = pv_cbor_encode(&source, &encoded);
    PV_CHECK(status == PV_OK);
    if (status != PV_OK) {
        pv_model_destroy(&source);
        return;
    }

    status = pv_model_init(&decoded, "decoded.pvlt");
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        status = pv_cbor_decode(encoded.data, encoded.len, &decoded);
        PV_CHECK(status == PV_OK);
    }

    if (status == PV_OK) {
        const pv_record *record;

        PV_CHECK(decoded.generation == source.generation);
        PV_CHECK(decoded.created_ms == source.created_ms);
        PV_CHECK(decoded.updated_ms == source.updated_ms);
        PV_CHECK(memcmp(decoded.device_id, source.device_id, PV_DEVICE_ID_BYTES) == 0);
        PV_CHECK(decoded.record_count == 1U);
        if (decoded.record_count == 1U) {
            record = &decoded.records[0];
            PV_CHECK(record->revision == 7U);
            PV_CHECK(record->flags == PV_RECORD_FAVORITE);
            PV_CHECK(slice_matches(&record->title, expected_title, sizeof expected_title - 1U));
            PV_CHECK(slice_matches(&record->username, expected_username, sizeof expected_username - 1U));
            PV_CHECK(slice_matches(&record->password, expected_password, sizeof expected_password));
            PV_CHECK(record->url_count == 2U);
            PV_CHECK(record->tag_count == 2U);
            PV_CHECK(record->field_count == 2U);
            if (record->field_count == 2U) {
                PV_CHECK(record->fields[1].flags == PV_FIELD_SECRET);
                PV_CHECK(
                    slice_matches(
                        &record->fields[1].value,
                        expected_secret_value,
                        sizeof expected_secret_value
                    )
                );
            }
        }
    }

    pv_model_destroy(&decoded);
    pv_buffer_secure_free(&encoded);
    pv_model_destroy(&source);
}

static void cbor_encoding_is_deterministic(void)
{
    pv_vault vault;
    pv_buffer first = {0};
    pv_buffer second = {0};
    pv_status first_status;
    pv_status second_status;

    (void)memset(&vault, 0, sizeof vault);
    first_status = sample_vault_init(&vault);
    PV_CHECK(first_status == PV_OK);
    if (first_status != PV_OK) {
        pv_model_destroy(&vault);
        return;
    }

    first_status = pv_cbor_encode(&vault, &first);
    second_status = pv_cbor_encode(&vault, &second);
    PV_CHECK(first_status == PV_OK);
    PV_CHECK(second_status == PV_OK);
    if (first_status == PV_OK && second_status == PV_OK) {
        PV_CHECK(first.len == second.len);
        if (first.len == second.len) {
            PV_CHECK(memcmp(first.data, second.data, first.len) == 0);
        }
    }

    pv_buffer_secure_free(&second);
    pv_buffer_secure_free(&first);
    pv_model_destroy(&vault);
}

static void cbor_decoder_rejects_truncation_trailing_data_and_indefinite_items(void)
{
    static const uint8_t indefinite_map[] = {0xbfU, 0xffU};
    pv_vault source;
    pv_vault destination;
    pv_buffer encoded = {0};
    uint8_t *with_trailing = NULL;
    uint8_t *nonminimal = NULL;
    pv_status status;

    (void)memset(&source, 0, sizeof source);
    (void)memset(&destination, 0, sizeof destination);
    status = sample_vault_init(&source);
    PV_CHECK(status == PV_OK);
    if (status != PV_OK) {
        pv_model_destroy(&source);
        return;
    }
    status = pv_cbor_encode(&source, &encoded);
    PV_CHECK(status == PV_OK);
    if (status != PV_OK) {
        pv_model_destroy(&source);
        return;
    }

    status = pv_model_init(&destination, "truncated.pvlt");
    PV_CHECK(status == PV_OK);
    if (status == PV_OK && encoded.len > 0U) {
        status = pv_cbor_decode(encoded.data, encoded.len - 1U, &destination);
        PV_CHECK(status != PV_OK);
    }
    pv_model_destroy(&destination);

    PV_CHECK(encoded.len > 2U);
    if (encoded.len > 2U) {
        nonminimal = malloc(encoded.len + 1U);
        PV_CHECK(nonminimal != NULL);
        if (nonminimal != NULL) {
            nonminimal[0] = encoded.data[0];
            nonminimal[1] = 0x18U;
            nonminimal[2] = 0x00U;
            (void)memcpy(nonminimal + 3U, encoded.data + 2U, encoded.len - 2U);
            (void)memset(&destination, 0, sizeof destination);
            status = pv_model_init(&destination, "nonminimal.pvlt");
            PV_CHECK(status == PV_OK);
            if (status == PV_OK) {
                status = pv_cbor_decode(nonminimal, encoded.len + 1U, &destination);
                PV_CHECK(status == PV_ERR_FORMAT);
            }
            pv_model_destroy(&destination);
            free(nonminimal);
        }
    }

    with_trailing = malloc(encoded.len + 1U);
    PV_CHECK(with_trailing != NULL);
    if (with_trailing != NULL) {
        (void)memcpy(with_trailing, encoded.data, encoded.len);
        with_trailing[encoded.len] = 0U;
        (void)memset(&destination, 0, sizeof destination);
        status = pv_model_init(&destination, "trailing.pvlt");
        PV_CHECK(status == PV_OK);
        if (status == PV_OK) {
            status = pv_cbor_decode(with_trailing, encoded.len + 1U, &destination);
            PV_CHECK(status != PV_OK);
        }
        pv_model_destroy(&destination);
        free(with_trailing);
    }

    (void)memset(&destination, 0, sizeof destination);
    status = pv_model_init(&destination, "indefinite.pvlt");
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        status = pv_cbor_decode(indefinite_map, sizeof indefinite_map, &destination);
        PV_CHECK(status != PV_OK);
    }
    pv_model_destroy(&destination);

    pv_buffer_secure_free(&encoded);
    pv_model_destroy(&source);
}

static void cbor_decoder_never_reports_semantic_errors_as_success(void)
{
    uint8_t expected_id[PV_RECORD_ID_BYTES];
    pv_vault source;
    pv_vault destination;
    pv_buffer encoded = {0};
    uint8_t *mutated = NULL;
    uint8_t *id;
    pv_status status;
    size_t index;

    status = sample_vault_init(&source);
    PV_CHECK(status == PV_OK);
    if (status != PV_OK) return;
    status = pv_cbor_encode(&source, &encoded);
    PV_CHECK(status == PV_OK);
    if (status != PV_OK) {
        pv_model_destroy(&source);
        return;
    }
    mutated = malloc(encoded.len);
    PV_CHECK(mutated != NULL);
    if (mutated == NULL) goto cleanup;

    (void)memcpy(mutated, encoded.data, encoded.len);
    mutated[0] = 0xa5U;
    status = pv_model_init(&destination, "bad-map-count.pvlt");
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        status = pv_cbor_decode(mutated, encoded.len, &destination);
        PV_CHECK(status == PV_ERR_FORMAT);
    }
    pv_model_destroy(&destination);

    for (index = 0U; index < sizeof expected_id; ++index) {
        expected_id[index] = (uint8_t)(0x80U + index);
    }
    (void)memcpy(mutated, encoded.data, encoded.len);
    id = find_bytes(mutated, encoded.len, expected_id, sizeof expected_id);
    PV_CHECK(id != NULL);
    if (id != NULL) {
        (void)memset(id, 0, sizeof expected_id);
        status = pv_model_init(&destination, "zero-id.pvlt");
        PV_CHECK(status == PV_OK);
        if (status == PV_OK) {
            status = pv_cbor_decode(mutated, encoded.len, &destination);
            PV_CHECK(status == PV_ERR_FORMAT);
        }
        pv_model_destroy(&destination);
    }

    (void)memcpy(mutated, encoded.data, encoded.len);
    id = find_bytes(mutated, encoded.len, expected_id, sizeof expected_id);
    PV_CHECK(id != NULL);
    if (id != NULL && (size_t)(id - mutated) + sizeof expected_id + 2U <= encoded.len) {
        uint8_t *const revision = id + sizeof expected_id + 1U;

        PV_CHECK(revision[-1] == 1U);
        *revision = 0U;
        status = pv_model_init(&destination, "zero-revision.pvlt");
        PV_CHECK(status == PV_OK);
        if (status == PV_OK) {
            status = pv_cbor_decode(mutated, encoded.len, &destination);
            PV_CHECK(status == PV_ERR_FORMAT);
        }
        pv_model_destroy(&destination);
    }

cleanup:
    free(mutated);
    pv_buffer_secure_free(&encoded);
    pv_model_destroy(&source);
}

static void model_rejects_fields_above_documented_limits(void)
{
    uint8_t oversized_title[PV_MAX_TITLE + 1U];
    pv_vault vault;
    pv_record source;
    pv_record *added = NULL;
    pv_status status;

    (void)memset(oversized_title, 'x', sizeof oversized_title);
    (void)memset(&vault, 0, sizeof vault);
    (void)memset(&source, 0, sizeof source);
    status = pv_model_init(&vault, "limits.pvlt");
    PV_CHECK(status == PV_OK);
    if (status != PV_OK) {
        return;
    }

    source.title.data = oversized_title;
    source.title.len = sizeof oversized_title;
    status = pv_model_add_record(&vault, &source, &added);
    PV_CHECK(status == PV_ERR_LIMIT);
    PV_CHECK(added == NULL);
    PV_CHECK(vault.record_count == 0U);

    pv_model_destroy(&vault);
}

void pv_test_cbor_suite(void)
{
    pv_test_run("cbor.roundtrip_preserves_all_fields", cbor_roundtrip_preserves_all_fields);
    pv_test_run("cbor.encoding_is_deterministic", cbor_encoding_is_deterministic);
    pv_test_run(
        "cbor.decoder_rejects_truncation_trailing_data_and_indefinite_items",
        cbor_decoder_rejects_truncation_trailing_data_and_indefinite_items
    );
    pv_test_run(
        "cbor.decoder_never_reports_semantic_errors_as_success",
        cbor_decoder_never_reports_semantic_errors_as_success
    );
    pv_test_run(
        "model.rejects_fields_above_documented_limits",
        model_rejects_fields_above_documented_limits
    );
}
