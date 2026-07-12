#include "pvault_internal.h"

#include <cbor.h>
#include <string.h>

#define PV_CBOR_SCHEMA_VERSION 1U

typedef struct cbor_writer {
    uint8_t *data;
    size_t len;
    size_t cap;
    pv_status status;
} cbor_writer;

typedef struct cbor_reader {
    const uint8_t *data;
    size_t len;
    size_t pos;
    pv_status status;
} cbor_reader;

static void writer_bytes(cbor_writer *const writer, const void *const data, const size_t len)
{
    size_t end;

    if (writer->status != PV_OK) {
        return;
    }
    if (len == 0U) {
        return;
    }
    if (data == NULL) {
        writer->status = PV_ERR_FORMAT;
        return;
    }
    if (!pv_size_add(writer->len, len, &end) || end > writer->cap) {
        writer->status = PV_ERR_LIMIT;
        return;
    }
    memcpy(writer->data + writer->len, data, len);
    writer->len = end;
}

static void writer_u8(cbor_writer *const writer, const uint8_t value)
{
    writer_bytes(writer, &value, 1U);
}

static void writer_type_value(cbor_writer *const writer, const uint8_t major, const uint64_t value)
{
    uint8_t bytes[9];
    size_t length;
    size_t i;

    if (value < 24U) {
        writer_u8(writer, (uint8_t)(major << 5U) | (uint8_t)value);
        return;
    }
    if (value <= UINT8_MAX) {
        bytes[0] = (uint8_t)(major << 5U) | 24U;
        bytes[1] = (uint8_t)value;
        length = 2U;
    } else if (value <= UINT16_MAX) {
        bytes[0] = (uint8_t)(major << 5U) | 25U;
        bytes[1] = (uint8_t)(value >> 8U);
        bytes[2] = (uint8_t)value;
        length = 3U;
    } else if (value <= UINT32_MAX) {
        bytes[0] = (uint8_t)(major << 5U) | 26U;
        length = 5U;
        for (i = 0U; i < 4U; ++i) {
            bytes[1U + i] = (uint8_t)(value >> ((3U - i) * 8U));
        }
    } else {
        bytes[0] = (uint8_t)(major << 5U) | 27U;
        length = 9U;
        for (i = 0U; i < 8U; ++i) {
            bytes[1U + i] = (uint8_t)(value >> ((7U - i) * 8U));
        }
    }
    writer_bytes(writer, bytes, length);
}

static void writer_uint(cbor_writer *const writer, const uint64_t value)
{
    writer_type_value(writer, 0U, value);
}

static void writer_map(cbor_writer *const writer, const size_t count)
{
    writer_type_value(writer, 5U, count);
}

static void writer_array(cbor_writer *const writer, const size_t count)
{
    writer_type_value(writer, 4U, count);
}

static void writer_blob(cbor_writer *const writer, const uint8_t major, const pv_slice *const slice)
{
    writer_type_value(writer, major, slice->len);
    writer_bytes(writer, slice->data, slice->len);
}

static void encode_field(cbor_writer *const writer, const pv_custom_field *const field)
{
    writer_map(writer, 3U);
    writer_uint(writer, 0U);
    writer_blob(writer, 3U, &field->name);
    writer_uint(writer, 1U);
    writer_blob(writer, 2U, &field->value);
    writer_uint(writer, 2U);
    writer_uint(writer, field->flags);
}

static void encode_record(cbor_writer *const writer, const pv_record *const record)
{
    size_t i;
    const pv_slice id = { .data = (uint8_t *)(uintptr_t)record->id, .len = PV_RECORD_ID_BYTES };

    writer_map(writer, 12U);
    writer_uint(writer, 0U);
    writer_blob(writer, 2U, &id);
    writer_uint(writer, 1U);
    writer_uint(writer, record->revision);
    writer_uint(writer, 2U);
    writer_uint(writer, (uint64_t)record->created_ms);
    writer_uint(writer, 3U);
    writer_uint(writer, (uint64_t)record->updated_ms);
    writer_uint(writer, 4U);
    writer_uint(writer, record->flags);
    writer_uint(writer, 5U);
    writer_blob(writer, 3U, &record->title);
    writer_uint(writer, 6U);
    writer_blob(writer, 3U, &record->username);
    writer_uint(writer, 7U);
    writer_blob(writer, 2U, &record->password);
    writer_uint(writer, 8U);
    writer_array(writer, record->url_count);
    for (i = 0U; i < record->url_count; ++i) {
        writer_blob(writer, 3U, &record->urls[i]);
    }
    writer_uint(writer, 9U);
    writer_blob(writer, 3U, &record->notes);
    writer_uint(writer, 10U);
    writer_array(writer, record->tag_count);
    for (i = 0U; i < record->tag_count; ++i) {
        writer_blob(writer, 3U, &record->tags[i]);
    }
    writer_uint(writer, 11U);
    writer_array(writer, record->field_count);
    for (i = 0U; i < record->field_count; ++i) {
        encode_field(writer, &record->fields[i]);
    }
}

pv_status pv_cbor_encode(const pv_vault *const vault, pv_buffer *const output)
{
    cbor_writer writer;
    size_t i;
    uint8_t device_id_aggregate = 0U;
    pv_slice device_id;

    if (vault == NULL || output == NULL || vault->created_ms < 0 || vault->updated_ms < 0) {
        return PV_ERR_USAGE;
    }
    *output = (pv_buffer){ .secure = true };
    if (vault->record_count > 0U && vault->records == NULL) {
        return PV_ERR_FORMAT;
    }
    for (i = 0U; i < PV_DEVICE_ID_BYTES; ++i) {
        device_id_aggregate |= vault->device_id[i];
    }
    if (device_id_aggregate == 0U) {
        return PV_ERR_FORMAT;
    }
    for (i = 0U; i < vault->record_count; ++i) {
        const pv_status status = pv_model_validate_record(&vault->records[i]);

        if (status != PV_OK) {
            return status;
        }
    }
    device_id = (pv_slice){
        .data = (uint8_t *)(uintptr_t)vault->device_id,
        .len = PV_DEVICE_ID_BYTES
    };
    output->data = sodium_malloc(PV_MAX_PLAINTEXT);
    if (output->data == NULL || sodium_mlock(output->data, PV_MAX_PLAINTEXT) != 0) {
        sodium_free(output->data);
        output->data = NULL;
        return PV_ERR_SECURE_MEMORY;
    }
    writer = (cbor_writer){
        .data = output->data,
        .cap = PV_MAX_PLAINTEXT,
        .status = PV_OK
    };
    writer_map(&writer, 6U);
    writer_uint(&writer, 0U);
    writer_uint(&writer, PV_CBOR_SCHEMA_VERSION);
    writer_uint(&writer, 1U);
    writer_uint(&writer, vault->generation);
    writer_uint(&writer, 2U);
    writer_blob(&writer, 2U, &device_id);
    writer_uint(&writer, 3U);
    writer_uint(&writer, (uint64_t)vault->created_ms);
    writer_uint(&writer, 4U);
    writer_uint(&writer, (uint64_t)vault->updated_ms);
    writer_uint(&writer, 5U);
    writer_array(&writer, vault->record_count);
    for (i = 0U; i < vault->record_count; ++i) {
        encode_record(&writer, &vault->records[i]);
    }
    if (writer.status != PV_OK) {
        pv_buffer_secure_free(output);
        return writer.status;
    }
    output->len = writer.len;
    return PV_OK;
}

static bool reader_take(cbor_reader *const reader, uint8_t *const out)
{
    if (reader->status != PV_OK || reader->pos >= reader->len) {
        reader->status = PV_ERR_FORMAT;
        return false;
    }
    *out = reader->data[reader->pos++];
    return true;
}

static bool reader_value(cbor_reader *const reader, const uint8_t expected_major, uint64_t *const value)
{
    uint8_t initial;
    uint8_t additional;
    unsigned width;
    uint64_t decoded = 0U;
    unsigned i;

    if (!reader_take(reader, &initial) || (initial >> 5U) != expected_major) {
        reader->status = PV_ERR_FORMAT;
        return false;
    }
    additional = initial & 0x1fU;
    if (additional < 24U) {
        *value = additional;
        return true;
    }
    if (additional == 24U) {
        width = 1U;
    } else if (additional == 25U) {
        width = 2U;
    } else if (additional == 26U) {
        width = 4U;
    } else if (additional == 27U) {
        width = 8U;
    } else {
        reader->status = PV_ERR_FORMAT;
        return false;
    }
    if (width > reader->len - reader->pos) {
        reader->status = PV_ERR_FORMAT;
        return false;
    }
    for (i = 0U; i < width; ++i) {
        decoded = (decoded << 8U) | reader->data[reader->pos++];
    }
    if ((width == 1U && decoded < 24U) ||
        (width == 2U && decoded <= UINT8_MAX) ||
        (width == 4U && decoded <= UINT16_MAX) ||
        (width == 8U && decoded <= UINT32_MAX)) {
        reader->status = PV_ERR_FORMAT;
        return false;
    }
    *value = decoded;
    return true;
}

static bool reader_expect_uint(cbor_reader *const reader, const uint64_t expected)
{
    uint64_t value;
    if (!reader_value(reader, 0U, &value) || value != expected) {
        reader->status = PV_ERR_FORMAT;
        return false;
    }
    return true;
}

static bool reader_fail(cbor_reader *const reader, const pv_status status)
{
    if (reader->status == PV_OK) {
        reader->status = status;
    }
    return false;
}

static bool bytes_all_zero(const uint8_t *const data, const size_t len)
{
    uint8_t aggregate = 0U;
    size_t i;

    for (i = 0U; i < len; ++i) {
        aggregate |= data[i];
    }
    return aggregate == 0U;
}

static bool reader_count(cbor_reader *const reader, const uint8_t major, const size_t maximum, size_t *const count)
{
    uint64_t value = 0U;

    if (!reader_value(reader, major, &value)) {
        return false;
    }
    if (value > maximum || value > SIZE_MAX) {
        reader->status = PV_ERR_LIMIT;
        return false;
    }
    *count = (size_t)value;
    return true;
}

static bool reader_slice(
    cbor_reader *const reader,
    const uint8_t major,
    const size_t maximum,
    pv_slice *const slice
)
{
    uint64_t length = 0U;

    if (!reader_value(reader, major, &length)) {
        return false;
    }
    if (length > maximum) {
        reader->status = PV_ERR_LIMIT;
        return false;
    }
    if (length > reader->len - reader->pos) {
        reader->status = PV_ERR_FORMAT;
        return false;
    }
    slice->data = (uint8_t *)(uintptr_t)(reader->data + reader->pos);
    slice->len = (size_t)length;
    reader->pos += (size_t)length;
    if (major == 3U && !pv_utf8_valid(slice->data, slice->len)) {
        reader->status = PV_ERR_FORMAT;
        return false;
    }
    return true;
}

static bool decode_field(cbor_reader *const reader, pv_custom_field *const field)
{
    size_t map_count;
    uint64_t flags;

    memset(field, 0, sizeof(*field));
    if (!reader_count(reader, 5U, 3U, &map_count)) return false;
    if (map_count != 3U) return reader_fail(reader, PV_ERR_FORMAT);
    if (!reader_expect_uint(reader, 0U) ||
        !reader_slice(reader, 3U, PV_MAX_FIELD_NAME, &field->name)) {
        return false;
    }
    if (field->name.len == 0U) {
        return reader_fail(reader, PV_ERR_FORMAT);
    }
    if (!reader_expect_uint(reader, 1U) ||
        !reader_slice(reader, 2U, PV_MAX_FIELD_VALUE, &field->value) ||
        !reader_expect_uint(reader, 2U) || !reader_value(reader, 0U, &flags)) {
        return false;
    }
    if (flags > UINT32_MAX || (flags & ~((uint64_t)PV_FIELD_SECRET)) != 0U) {
        return reader_fail(reader, PV_ERR_FORMAT);
    }
    field->flags = (uint32_t)flags;
    return true;
}

static bool decode_record(cbor_reader *const reader, pv_vault *const vault)
{
    pv_record temporary;
    pv_slice id;
    pv_slice urls[PV_MAX_COLLECTION_ITEMS];
    pv_slice tags[PV_MAX_COLLECTION_ITEMS];
    pv_custom_field fields[PV_MAX_COLLECTION_ITEMS];
    uint64_t value;
    size_t count;
    size_t i;
    pv_status status;

    memset(&temporary, 0, sizeof(temporary));
    if (!reader_count(reader, 5U, 12U, &count)) goto fail;
    if (count != 12U) {
        (void)reader_fail(reader, PV_ERR_FORMAT);
        goto fail;
    }
    if (!reader_expect_uint(reader, 0U) ||
        !reader_slice(reader, 2U, PV_RECORD_ID_BYTES, &id)) goto fail;
    if (id.len != PV_RECORD_ID_BYTES || bytes_all_zero(id.data, id.len)) {
        (void)reader_fail(reader, PV_ERR_FORMAT);
        goto fail;
    }
    memcpy(temporary.id, id.data, sizeof(temporary.id));
    if (!reader_expect_uint(reader, 1U) || !reader_value(reader, 0U, &temporary.revision)) goto fail;
    if (temporary.revision == 0U) {
        (void)reader_fail(reader, PV_ERR_FORMAT);
        goto fail;
    }
    if (!reader_expect_uint(reader, 2U) || !reader_value(reader, 0U, &value)) goto fail;
    if (value > INT64_MAX) {
        (void)reader_fail(reader, PV_ERR_FORMAT);
        goto fail;
    }
    temporary.created_ms = (int64_t)value;
    if (!reader_expect_uint(reader, 3U) || !reader_value(reader, 0U, &value)) goto fail;
    if (value > INT64_MAX) {
        (void)reader_fail(reader, PV_ERR_FORMAT);
        goto fail;
    }
    temporary.updated_ms = (int64_t)value;
    if (!reader_expect_uint(reader, 4U) || !reader_value(reader, 0U, &value)) goto fail;
    if (value > UINT32_MAX || (value & ~((uint64_t)(PV_RECORD_DELETED | PV_RECORD_FAVORITE))) != 0U) {
        (void)reader_fail(reader, PV_ERR_FORMAT);
        goto fail;
    }
    temporary.flags = (uint32_t)value;
    if (!reader_expect_uint(reader, 5U) ||
        !reader_slice(reader, 3U, PV_MAX_TITLE, &temporary.title)) goto fail;
    if (temporary.title.len == 0U) {
        (void)reader_fail(reader, PV_ERR_FORMAT);
        goto fail;
    }
    if (!reader_expect_uint(reader, 6U) ||
        !reader_slice(reader, 3U, PV_MAX_USERNAME, &temporary.username) ||
        !reader_expect_uint(reader, 7U) ||
        !reader_slice(reader, 2U, PV_MAX_PASSWORD, &temporary.password) ||
        !reader_expect_uint(reader, 8U) ||
        !reader_count(reader, 4U, PV_MAX_COLLECTION_ITEMS, &count)) goto fail;
    temporary.urls = urls;
    temporary.url_count = count;
    for (i = 0U; i < count; ++i) {
        if (!reader_slice(reader, 3U, PV_MAX_URL, &urls[i])) {
            goto fail;
        }
    }
    if (!reader_expect_uint(reader, 9U) || !reader_slice(reader, 3U, PV_MAX_NOTES, &temporary.notes) ||
        !reader_expect_uint(reader, 10U) || !reader_count(reader, 4U, PV_MAX_COLLECTION_ITEMS, &count)) {
        goto fail;
    }
    temporary.tags = tags;
    temporary.tag_count = count;
    for (i = 0U; i < count; ++i) {
        if (!reader_slice(reader, 3U, PV_MAX_TAG, &tags[i])) {
            goto fail;
        }
    }
    if (!reader_expect_uint(reader, 11U) || !reader_count(reader, 4U, PV_MAX_COLLECTION_ITEMS, &count)) {
        goto fail;
    }
    temporary.fields = fields;
    temporary.field_count = count;
    for (i = 0U; i < count; ++i) {
        if (!decode_field(reader, &fields[i])) {
            goto fail;
        }
    }
    status = pv_model_add_record(vault, &temporary, NULL);
    sodium_memzero(fields, sizeof(fields));
    sodium_memzero(tags, sizeof(tags));
    sodium_memzero(urls, sizeof(urls));
    sodium_memzero(&temporary, sizeof(temporary));
    if (status != PV_OK) {
        reader->status = status == PV_ERR_EXISTS ? PV_ERR_FORMAT : status;
        return false;
    }
    return true;

fail:
    sodium_memzero(fields, sizeof(fields));
    sodium_memzero(tags, sizeof(tags));
    sodium_memzero(urls, sizeof(urls));
    sodium_memzero(&temporary, sizeof(temporary));
    if (reader->status == PV_OK) {
        reader->status = PV_ERR_FORMAT;
    }
    return false;
}

static bool libcbor_well_formed(const uint8_t *const input, const size_t input_len)
{
    size_t offset = 0U;

    while (offset < input_len) {
        const struct cbor_decoder_result result = cbor_stream_decode(
            input + offset,
            input_len - offset,
            &cbor_empty_callbacks,
            NULL
        );
        if (result.status != CBOR_DECODER_FINISHED || result.read == 0U || result.read > input_len - offset) {
            return false;
        }
        offset += result.read;
    }
    return offset == input_len;
}

pv_status pv_cbor_decode(const uint8_t *const input, const size_t input_len, pv_vault *const vault)
{
    cbor_reader reader;
    size_t map_count;
    size_t record_count;
    size_t i;
    pv_slice device_id;
    uint64_t value;
    int64_t top_created;
    int64_t top_updated;
    pv_status status;
    uint8_t device_id_aggregate = 0U;

    if (input == NULL || input_len == 0U || input_len > PV_MAX_PLAINTEXT || vault == NULL ||
        vault->record_count != 0U) {
        return PV_ERR_USAGE;
    }
    if (!libcbor_well_formed(input, input_len)) {
        return PV_ERR_FORMAT;
    }
    reader = (cbor_reader){ .data = input, .len = input_len, .status = PV_OK };
    if (!reader_count(&reader, 5U, 6U, &map_count)) {
        return reader.status;
    }
    if (map_count != 6U) {
        return PV_ERR_FORMAT;
    }
    if (!reader_expect_uint(&reader, 0U) || !reader_expect_uint(&reader, PV_CBOR_SCHEMA_VERSION) ||
        !reader_expect_uint(&reader, 1U) || !reader_value(&reader, 0U, &vault->generation) ||
        !reader_expect_uint(&reader, 2U) || !reader_slice(&reader, 2U, PV_DEVICE_ID_BYTES, &device_id)) {
        return reader.status;
    }
    if (device_id.len != PV_DEVICE_ID_BYTES || bytes_all_zero(device_id.data, device_id.len)) {
        return PV_ERR_FORMAT;
    }
    memcpy(vault->device_id, device_id.data, PV_DEVICE_ID_BYTES);
    for (i = 0U; i < PV_DEVICE_ID_BYTES; ++i) {
        device_id_aggregate |= vault->device_id[i];
    }
    if (device_id_aggregate == 0U) {
        return PV_ERR_FORMAT;
    }
    if (!reader_expect_uint(&reader, 3U) || !reader_value(&reader, 0U, &value)) {
        return reader.status;
    }
    if (value > INT64_MAX) return PV_ERR_FORMAT;
    top_created = (int64_t)value;
    if (!reader_expect_uint(&reader, 4U) || !reader_value(&reader, 0U, &value)) {
        return reader.status;
    }
    if (value > INT64_MAX) return PV_ERR_FORMAT;
    top_updated = (int64_t)value;
    if (!reader_expect_uint(&reader, 5U) ||
        !reader_count(&reader, 4U, PV_MAX_PLAINTEXT / 64U, &record_count)) {
        return reader.status;
    }
    for (i = 0U; i < record_count; ++i) {
        if (!decode_record(&reader, vault)) {
            return reader.status == PV_OK ? PV_ERR_FORMAT : reader.status;
        }
    }
    if (reader.pos != reader.len) {
        return PV_ERR_FORMAT;
    }
    vault->created_ms = top_created;
    vault->updated_ms = top_updated;
    vault->dirty = false;
    status = pv_arena_set_readonly(&vault->arena);
    return status;
}
