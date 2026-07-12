#include "pvault_internal.h"

#include <string.h>

#define PV_INITIAL_RECORD_CAPACITY 16U

static bool id_is_zero(const uint8_t *const id, const size_t len)
{
    size_t i;
    uint8_t aggregate = 0U;

    for (i = 0U; i < len; ++i) {
        aggregate |= id[i];
    }
    return aggregate == 0U;
}

static bool text_slice_valid(const pv_slice *const slice, const bool allow_empty)
{
    return slice != NULL && (slice->data != NULL || slice->len == 0U) &&
        (allow_empty || slice->len > 0U) && pv_utf8_valid(slice->data, slice->len);
}

static pv_status validate_record_fields(const pv_record *const record)
{
    size_t i;

    if (record == NULL) {
        return PV_ERR_USAGE;
    }
    if (record->title.len > PV_MAX_TITLE || record->username.len > PV_MAX_USERNAME ||
        record->password.len > PV_MAX_PASSWORD || record->notes.len > PV_MAX_NOTES ||
        record->url_count > PV_MAX_COLLECTION_ITEMS || record->tag_count > PV_MAX_COLLECTION_ITEMS ||
        record->field_count > PV_MAX_COLLECTION_ITEMS) {
        return PV_ERR_LIMIT;
    }
    if (record->created_ms < 0 || record->updated_ms < 0 ||
        (record->flags & ~(PV_RECORD_DELETED | PV_RECORD_FAVORITE)) != 0U ||
        !text_slice_valid(&record->title, false) ||
        !text_slice_valid(&record->username, true) ||
        (record->password.data == NULL && record->password.len != 0U) ||
        !text_slice_valid(&record->notes, true) ||
        (record->urls == NULL && record->url_count != 0U) ||
        (record->tags == NULL && record->tag_count != 0U) ||
        (record->fields == NULL && record->field_count != 0U)) {
        return PV_ERR_FORMAT;
    }
    for (i = 0U; i < record->url_count; ++i) {
        if (record->urls[i].len > PV_MAX_URL) return PV_ERR_LIMIT;
        if (!text_slice_valid(&record->urls[i], true)) {
            return PV_ERR_FORMAT;
        }
    }
    for (i = 0U; i < record->tag_count; ++i) {
        if (record->tags[i].len > PV_MAX_TAG) return PV_ERR_LIMIT;
        if (!text_slice_valid(&record->tags[i], true)) {
            return PV_ERR_FORMAT;
        }
    }
    for (i = 0U; i < record->field_count; ++i) {
        const pv_custom_field *const field = &record->fields[i];

        if (field->name.len > PV_MAX_FIELD_NAME || field->value.len > PV_MAX_FIELD_VALUE) {
            return PV_ERR_LIMIT;
        }
        if (!text_slice_valid(&field->name, false) ||
            (field->value.data == NULL && field->value.len != 0U) ||
            (field->flags & ~PV_FIELD_SECRET) != 0U) {
            return PV_ERR_FORMAT;
        }
    }
    return PV_OK;
}

pv_status pv_model_validate_record(const pv_record *const record)
{
    const pv_status status = validate_record_fields(record);

    if (status != PV_OK) {
        return status;
    }
    if (record->revision == 0U || id_is_zero(record->id, sizeof(record->id))) {
        return PV_ERR_FORMAT;
    }
    return PV_OK;
}

pv_status pv_model_init(pv_vault *const vault, const char *const path)
{
    pv_status status;

    if (vault == NULL || path == NULL || strlen(path) >= sizeof(vault->path)) {
        return PV_ERR_USAGE;
    }
    memset(vault, 0, sizeof(*vault));
    status = pv_arena_init(&vault->arena, PV_ARENA_CAPACITY);
    if (status != PV_OK) {
        return status;
    }
    vault->vmk = sodium_malloc(PV_WRAP_KEY_BYTES);
    if (vault->vmk == NULL) {
        pv_arena_destroy(&vault->arena);
        return PV_ERR_NOMEM;
    }
    if (sodium_mlock(vault->vmk, PV_WRAP_KEY_BYTES) != 0) {
        sodium_free(vault->vmk);
        vault->vmk = NULL;
        pv_arena_destroy(&vault->arena);
        return PV_ERR_SECURE_MEMORY;
    }
    sodium_memzero(vault->vmk, PV_WRAP_KEY_BYTES);
    vault->records = pv_arena_alloc(
        &vault->arena,
        PV_INITIAL_RECORD_CAPACITY * sizeof(*vault->records),
        _Alignof(pv_record)
    );
    if (vault->records == NULL) {
        pv_model_destroy(vault);
        return PV_ERR_LIMIT;
    }
    vault->record_capacity = PV_INITIAL_RECORD_CAPACITY;
    (void)strcpy(vault->path, path);
    return PV_OK;
}

void pv_model_destroy(pv_vault *const vault)
{
    if (vault == NULL) {
        return;
    }
    if (vault->vmk != NULL) {
        sodium_free(vault->vmk);
        vault->vmk = NULL;
    }
    pv_arena_destroy(&vault->arena);
    sodium_memzero(vault, sizeof(*vault));
}

static pv_status ensure_record_capacity(pv_vault *const vault)
{
    size_t new_capacity;
    size_t bytes;
    pv_record *records;

    if (vault->record_count < vault->record_capacity) {
        return PV_OK;
    }
    if (vault->record_capacity >= SIZE_MAX / 2U) {
        return PV_ERR_LIMIT;
    }
    new_capacity = vault->record_capacity * 2U;
    if (!pv_size_mul(new_capacity, sizeof(*records), &bytes)) {
        return PV_ERR_LIMIT;
    }
    records = pv_arena_alloc(&vault->arena, bytes, _Alignof(pv_record));
    if (records == NULL) {
        return PV_ERR_LIMIT;
    }
    memcpy(records, vault->records, vault->record_count * sizeof(*records));
    vault->records = records;
    vault->record_capacity = new_capacity;
    return PV_OK;
}

static pv_status copy_slices(
    pv_arena *const arena,
    pv_slice **const destination,
    const pv_slice *const source,
    const size_t count,
    const size_t max_len
)
{
    size_t i;
    pv_slice *items;

    *destination = NULL;
    if (count == 0U) {
        return PV_OK;
    }
    if (count > PV_MAX_COLLECTION_ITEMS) {
        return PV_ERR_LIMIT;
    }
    items = pv_arena_alloc(arena, count * sizeof(*items), _Alignof(pv_slice));
    if (items == NULL) {
        return PV_ERR_LIMIT;
    }
    for (i = 0U; i < count; ++i) {
        const pv_status status = pv_arena_copy(arena, &items[i], source[i].data, source[i].len, max_len);
        if (status != PV_OK) {
            return status;
        }
    }
    *destination = items;
    return PV_OK;
}

static pv_status copy_fields(
    pv_arena *const arena,
    pv_custom_field **const destination,
    const pv_custom_field *const source,
    const size_t count
)
{
    size_t i;
    pv_custom_field *items;

    *destination = NULL;
    if (count == 0U) {
        return PV_OK;
    }
    if (count > PV_MAX_COLLECTION_ITEMS) {
        return PV_ERR_LIMIT;
    }
    items = pv_arena_alloc(arena, count * sizeof(*items), _Alignof(pv_custom_field));
    if (items == NULL) {
        return PV_ERR_LIMIT;
    }
    for (i = 0U; i < count; ++i) {
        pv_status status = pv_arena_copy(
            arena,
            &items[i].name,
            source[i].name.data,
            source[i].name.len,
            PV_MAX_FIELD_NAME
        );
        if (status != PV_OK) {
            return status;
        }
        status = pv_arena_copy(
            arena,
            &items[i].value,
            source[i].value.data,
            source[i].value.len,
            PV_MAX_FIELD_VALUE
        );
        if (status != PV_OK) {
            return status;
        }
        items[i].flags = source[i].flags;
    }
    *destination = items;
    return PV_OK;
}

pv_status pv_model_add_record(pv_vault *const vault, const pv_record *const source, pv_record **const out)
{
    pv_record *record;
    pv_status status;
    const int64_t now = pv_now_ms();

    if (vault == NULL || source == NULL) {
        return PV_ERR_USAGE;
    }
    status = validate_record_fields(source);
    if (status != PV_OK) {
        return status;
    }
    if (source->revision != 0U && id_is_zero(source->id, sizeof(source->id))) {
        return PV_ERR_FORMAT;
    }
    if (vault->arena.readonly) {
        status = pv_arena_set_readwrite(&vault->arena);
        if (status != PV_OK) {
            return status;
        }
    }
    status = ensure_record_capacity(vault);
    if (status != PV_OK) {
        return status;
    }
    record = &vault->records[vault->record_count];
    sodium_memzero(record, sizeof(*record));
    memcpy(record->id, source->id, sizeof(record->id));
    if (id_is_zero(record->id, sizeof(record->id))) {
        do {
            randombytes_buf(record->id, sizeof(record->id));
        } while (id_is_zero(record->id, sizeof(record->id)) || pv_model_find_id(vault, record->id) != NULL);
    } else if (pv_model_find_id(vault, record->id) != NULL) {
        return PV_ERR_EXISTS;
    }
    record->revision = source->revision == 0U ? 1U : source->revision;
    record->created_ms = source->revision == 0U && source->created_ms == 0 ? now : source->created_ms;
    record->updated_ms = source->revision == 0U && source->updated_ms == 0 ? now : source->updated_ms;
    record->flags = source->flags;
    status = pv_arena_copy(&vault->arena, &record->title, source->title.data, source->title.len, PV_MAX_TITLE);
    if (status != PV_OK || record->title.len == 0U) {
        return status == PV_OK ? PV_ERR_USAGE : status;
    }
    status = pv_arena_copy(
        &vault->arena,
        &record->username,
        source->username.data,
        source->username.len,
        PV_MAX_USERNAME
    );
    if (status != PV_OK) {
        return status;
    }
    status = pv_arena_copy(
        &vault->arena,
        &record->password,
        source->password.data,
        source->password.len,
        PV_MAX_PASSWORD
    );
    if (status != PV_OK) {
        return status;
    }
    status = pv_arena_copy(&vault->arena, &record->notes, source->notes.data, source->notes.len, PV_MAX_NOTES);
    if (status != PV_OK) {
        return status;
    }
    status = copy_slices(&vault->arena, &record->urls, source->urls, source->url_count, PV_MAX_URL);
    if (status != PV_OK) {
        return status;
    }
    record->url_count = source->url_count;
    status = copy_slices(&vault->arena, &record->tags, source->tags, source->tag_count, PV_MAX_TAG);
    if (status != PV_OK) {
        return status;
    }
    record->tag_count = source->tag_count;
    status = copy_fields(&vault->arena, &record->fields, source->fields, source->field_count);
    if (status != PV_OK) {
        return status;
    }
    record->field_count = source->field_count;
    ++vault->record_count;
    vault->dirty = true;
    vault->updated_ms = now;
    if (out != NULL) {
        *out = record;
    }
    return PV_OK;
}

pv_record *pv_model_find_id(pv_vault *const vault, const uint8_t id[PV_RECORD_ID_BYTES])
{
    size_t i;

    if (vault == NULL || id == NULL) {
        return NULL;
    }
    for (i = 0U; i < vault->record_count; ++i) {
        if (sodium_memcmp(vault->records[i].id, id, PV_RECORD_ID_BYTES) == 0) {
            return &vault->records[i];
        }
    }
    return NULL;
}

static bool record_matches(const pv_record *const record, const char *const query)
{
    size_t i;

    if (pv_slice_contains_cstr(&record->title, query, true) ||
        pv_slice_contains_cstr(&record->username, query, true)) {
        return true;
    }
    for (i = 0U; i < record->url_count; ++i) {
        if (pv_slice_contains_cstr(&record->urls[i], query, true)) {
            return true;
        }
    }
    for (i = 0U; i < record->tag_count; ++i) {
        if (pv_slice_contains_cstr(&record->tags[i], query, true)) {
            return true;
        }
    }
    return false;
}

pv_record *pv_model_find(pv_vault *const vault, const char *const query, size_t *const matches)
{
    size_t i;
    size_t count = 0U;
    pv_record *first = NULL;
    uint8_t id[PV_RECORD_ID_BYTES];

    if (matches != NULL) {
        *matches = 0U;
    }
    if (vault == NULL || query == NULL || query[0] == '\0') {
        return NULL;
    }
    if (pv_hex_decode(query, id, sizeof(id))) {
        first = pv_model_find_id(vault, id);
        if (first != NULL && (first->flags & PV_RECORD_DELETED) == 0U) {
            if (matches != NULL) {
                *matches = 1U;
            }
            return first;
        }
    }
    for (i = 0U; i < vault->record_count; ++i) {
        pv_record *const record = &vault->records[i];
        if ((record->flags & PV_RECORD_DELETED) != 0U || !record_matches(record, query)) {
            continue;
        }
        if (first == NULL) {
            first = record;
        }
        ++count;
    }
    if (matches != NULL) {
        *matches = count;
    }
    return first;
}

pv_status pv_model_delete(pv_vault *const vault, pv_record *const record)
{
    size_t i;
    pv_status status;

    if (vault == NULL || record == NULL || (record->flags & PV_RECORD_DELETED) != 0U) {
        return PV_ERR_USAGE;
    }
    if (record->revision == UINT64_MAX) {
        return PV_ERR_LIMIT;
    }
    if (vault->arena.readonly) {
        status = pv_arena_set_readwrite(&vault->arena);
        if (status != PV_OK) {
            return status;
        }
    }
    if (record->username.data != NULL) {
        sodium_memzero(record->username.data, record->username.len);
    }
    if (record->password.data != NULL) {
        sodium_memzero(record->password.data, record->password.len);
    }
    if (record->notes.data != NULL) {
        sodium_memzero(record->notes.data, record->notes.len);
    }
    for (i = 0U; i < record->url_count; ++i) {
        sodium_memzero(record->urls[i].data, record->urls[i].len);
    }
    for (i = 0U; i < record->tag_count; ++i) {
        sodium_memzero(record->tags[i].data, record->tags[i].len);
    }
    for (i = 0U; i < record->field_count; ++i) {
        sodium_memzero(record->fields[i].name.data, record->fields[i].name.len);
        sodium_memzero(record->fields[i].value.data, record->fields[i].value.len);
    }
    record->username = (pv_slice){ 0 };
    record->password = (pv_slice){ 0 };
    record->notes = (pv_slice){ 0 };
    record->url_count = 0U;
    record->tag_count = 0U;
    record->field_count = 0U;
    record->flags |= PV_RECORD_DELETED;
    ++record->revision;
    record->updated_ms = pv_now_ms();
    vault->dirty = true;
    vault->updated_ms = record->updated_ms;
    return PV_OK;
}

pv_status pv_model_clone(pv_vault *const destination, const pv_vault *const source)
{
    size_t i;
    pv_status status;

    if (destination == NULL || source == NULL) {
        return PV_ERR_USAGE;
    }
    status = pv_model_init(destination, source->path);
    if (status != PV_OK) {
        return status;
    }
    memcpy(destination->vault_id, source->vault_id, sizeof(destination->vault_id));
    memcpy(destination->device_id, source->device_id, sizeof(destination->device_id));
    memcpy(destination->vmk, source->vmk, PV_WRAP_KEY_BYTES);
    memcpy(destination->source_hash, source->source_hash, sizeof(destination->source_hash));
    destination->generation = source->generation;
    destination->created_ms = source->created_ms;
    destination->updated_ms = source->updated_ms;
    for (i = 0U; i < source->record_count; ++i) {
        status = pv_model_add_record(destination, &source->records[i], NULL);
        if (status != PV_OK) {
            pv_model_destroy(destination);
            return status;
        }
    }
    destination->created_ms = source->created_ms;
    destination->updated_ms = source->updated_ms;
    destination->dirty = source->dirty;
    return PV_OK;
}
