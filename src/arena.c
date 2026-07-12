#include "pvault_internal.h"

#include <string.h>

pv_status pv_arena_init(pv_arena *const arena, const size_t capacity)
{
    if (arena == NULL || capacity == 0U || capacity > PV_MAX_PLAINTEXT) {
        return PV_ERR_USAGE;
    }
    memset(arena, 0, sizeof(*arena));
    arena->base = sodium_malloc(capacity);
    if (arena->base == NULL) {
        return PV_ERR_NOMEM;
    }
    if (sodium_mlock(arena->base, capacity) != 0) {
        sodium_free(arena->base);
        arena->base = NULL;
        return PV_ERR_SECURE_MEMORY;
    }
    sodium_memzero(arena->base, capacity);
    arena->capacity = capacity;
    return PV_OK;
}

void *pv_arena_alloc(pv_arena *const arena, const size_t size, const size_t alignment)
{
    size_t mask;
    size_t aligned;
    size_t end;
    void *result;

    if (arena == NULL || arena->base == NULL || arena->readonly || size == 0U ||
        alignment == 0U || (alignment & (alignment - 1U)) != 0U) {
        return NULL;
    }
    mask = alignment - 1U;
    if (!pv_size_add(arena->used, mask, &aligned)) {
        return NULL;
    }
    aligned &= ~mask;
    if (!pv_size_add(aligned, size, &end) || end > arena->capacity) {
        return NULL;
    }
    result = arena->base + aligned;
    sodium_memzero(result, size);
    arena->used = end;
    return result;
}

pv_status pv_arena_copy(
    pv_arena *const arena,
    pv_slice *const out,
    const void *const data,
    const size_t len,
    const size_t max_len
)
{
    uint8_t *destination;

    if (arena == NULL || out == NULL || (data == NULL && len != 0U) || len > max_len) {
        return len > max_len ? PV_ERR_LIMIT : PV_ERR_USAGE;
    }
    out->data = NULL;
    out->len = 0U;
    if (len == 0U) {
        return PV_OK;
    }
    destination = pv_arena_alloc(arena, len + 1U, _Alignof(uint8_t));
    if (destination == NULL) {
        return PV_ERR_LIMIT;
    }
    memcpy(destination, data, len);
    destination[len] = 0U;
    out->data = destination;
    out->len = len;
    return PV_OK;
}

pv_status pv_arena_set_readonly(pv_arena *const arena)
{
    if (arena == NULL || arena->base == NULL) {
        return PV_ERR_USAGE;
    }
    if (sodium_mprotect_readonly(arena->base) != 0) {
        return PV_ERR_SECURE_MEMORY;
    }
    arena->readonly = true;
    return PV_OK;
}

pv_status pv_arena_set_readwrite(pv_arena *const arena)
{
    if (arena == NULL || arena->base == NULL) {
        return PV_ERR_USAGE;
    }
    if (sodium_mprotect_readwrite(arena->base) != 0) {
        return PV_ERR_SECURE_MEMORY;
    }
    arena->readonly = false;
    return PV_OK;
}

void pv_arena_reset(pv_arena *const arena)
{
    if (arena == NULL || arena->base == NULL) {
        return;
    }
    if (arena->readonly) {
        (void)pv_arena_set_readwrite(arena);
    }
    sodium_memzero(arena->base, arena->capacity);
    arena->used = 0U;
}

void pv_arena_destroy(pv_arena *const arena)
{
    if (arena == NULL) {
        return;
    }
    if (arena->base != NULL) {
        if (arena->readonly) {
            (void)pv_arena_set_readwrite(arena);
        }
        sodium_free(arena->base);
    }
    memset(arena, 0, sizeof(*arena));
}
