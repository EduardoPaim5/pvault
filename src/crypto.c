#include "pvault_internal.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t pv_magic[PV_MAGIC_LEN] = { 'P', 'V', 'L', 'T', 0x0dU, 0x0aU, 0x1aU, 0x0aU };
static const char body_kdf_context[crypto_kdf_CONTEXTBYTES] = { 'P', 'V', 'B', 'O', 'D', 'Y', '0', '1' };
static const char recovery_kdf_context[crypto_kdf_CONTEXTBYTES] = { 'P', 'V', 'R', 'E', 'C', 'V', '0', '1' };

#define PV_PASSWORD_AAD_LEN 76U
#define PV_RECOVERY_AAD_LEN 44U
static void put_u16_le(uint8_t *const out, const uint16_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8U);
}

static void put_u32_le(uint8_t *const out, const uint32_t value)
{
    size_t i;
    for (i = 0U; i < 4U; ++i) {
        out[i] = (uint8_t)(value >> (i * 8U));
    }
}

static void put_u64_le(uint8_t *const out, const uint64_t value)
{
    size_t i;
    for (i = 0U; i < 8U; ++i) {
        out[i] = (uint8_t)(value >> (i * 8U));
    }
}

static uint16_t get_u16_le(const uint8_t *const in)
{
    return (uint16_t)in[0] | (uint16_t)((uint16_t)in[1] << 8U);
}

static uint32_t get_u32_le(const uint8_t *const in)
{
    size_t i;
    uint32_t value = 0U;
    for (i = 0U; i < 4U; ++i) {
        value |= (uint32_t)in[i] << (i * 8U);
    }
    return value;
}

static uint64_t get_u64_le(const uint8_t *const in)
{
    size_t i;
    uint64_t value = 0U;
    for (i = 0U; i < 8U; ++i) {
        value |= (uint64_t)in[i] << (i * 8U);
    }
    return value;
}

pv_status pv_header_encode(const pv_file_header *const header, uint8_t output[PV_FILE_HEADER_LEN])
{
    if (header == NULL || output == NULL) {
        return PV_ERR_USAGE;
    }
    memcpy(output, header->magic, PV_MAGIC_LEN);
    put_u16_le(output + 8U, header->major);
    put_u16_le(output + 10U, header->minor);
    put_u32_le(output + 12U, header->header_len);
    put_u32_le(output + 16U, header->flags);
    memcpy(output + 20U, header->vault_id, PV_VAULT_ID_BYTES);
    put_u16_le(output + 36U, header->kdf_id);
    put_u16_le(output + 38U, header->wrap_aead_id);
    put_u16_le(output + 40U, header->body_aead_id);
    put_u16_le(output + 42U, header->slot_count);
    put_u64_le(output + 44U, header->password_slot.opslimit);
    put_u64_le(output + 52U, header->password_slot.memlimit);
    memcpy(output + 60U, header->password_slot.salt, PV_SALT_BYTES);
    memcpy(output + 76U, header->password_slot.nonce, PV_WRAP_NONCE_BYTES);
    memcpy(output + 100U, header->password_slot.wrapped_vmk, PV_WRAPPED_VMK_BYTES);
    memcpy(output + 148U, header->recovery_slot.nonce, PV_WRAP_NONCE_BYTES);
    memcpy(output + 172U, header->recovery_slot.wrapped_vmk, PV_WRAPPED_VMK_BYTES);
    memcpy(output + 220U, header->body_nonce, PV_WRAP_NONCE_BYTES);
    put_u64_le(output + 244U, header->body_ciphertext_len);
    return PV_OK;
}

pv_status pv_header_decode(const uint8_t input[PV_FILE_HEADER_LEN], pv_file_header *const header)
{
    uint64_t maximum_ciphertext;
    uint8_t id_aggregate = 0U;
    size_t i;

    if (input == NULL || header == NULL) {
        return PV_ERR_USAGE;
    }
    sodium_memzero(header, sizeof(*header));
    memcpy(header->magic, input, PV_MAGIC_LEN);
    header->major = get_u16_le(input + 8U);
    header->minor = get_u16_le(input + 10U);
    header->header_len = get_u32_le(input + 12U);
    header->flags = get_u32_le(input + 16U);
    memcpy(header->vault_id, input + 20U, PV_VAULT_ID_BYTES);
    header->kdf_id = get_u16_le(input + 36U);
    header->wrap_aead_id = get_u16_le(input + 38U);
    header->body_aead_id = get_u16_le(input + 40U);
    header->slot_count = get_u16_le(input + 42U);
    header->password_slot.opslimit = get_u64_le(input + 44U);
    header->password_slot.memlimit = get_u64_le(input + 52U);
    memcpy(header->password_slot.salt, input + 60U, PV_SALT_BYTES);
    memcpy(header->password_slot.nonce, input + 76U, PV_WRAP_NONCE_BYTES);
    memcpy(header->password_slot.wrapped_vmk, input + 100U, PV_WRAPPED_VMK_BYTES);
    memcpy(header->recovery_slot.nonce, input + 148U, PV_WRAP_NONCE_BYTES);
    memcpy(header->recovery_slot.wrapped_vmk, input + 172U, PV_WRAPPED_VMK_BYTES);
    memcpy(header->body_nonce, input + 220U, PV_WRAP_NONCE_BYTES);
    header->body_ciphertext_len = get_u64_le(input + 244U);

    for (i = 0U; i < PV_VAULT_ID_BYTES; ++i) {
        id_aggregate |= header->vault_id[i];
    }

    maximum_ciphertext = (uint64_t)PV_MAX_PLAINTEXT + PV_BODY_TAG_BYTES;
    if (sodium_memcmp(header->magic, pv_magic, PV_MAGIC_LEN) != 0) {
        sodium_memzero(header, sizeof(*header));
        return PV_ERR_FORMAT;
    }
    /* This is the exact v1.0 decoder; future minors require explicit dispatch. */
    if (header->major != PV_FILE_MAJOR || header->minor != PV_FILE_MINOR) {
        sodium_memzero(header, sizeof(*header));
        return PV_ERR_UNSUPPORTED;
    }
    if (id_aggregate == 0U || header->header_len != PV_FILE_HEADER_LEN || header->flags != 0U ||
        header->kdf_id != PV_KDF_ARGON2ID13 ||
        header->wrap_aead_id != PV_AEAD_XCHACHA20POLY1305 ||
        header->body_aead_id != PV_AEAD_XCHACHA20POLY1305 ||
        header->slot_count != 2U ||
        header->password_slot.opslimit < PV_V1_PASSWORD_OPSLIMIT_MIN ||
        header->password_slot.opslimit > PV_V1_PASSWORD_OPSLIMIT_MAX ||
        header->password_slot.memlimit < PV_V1_PASSWORD_MEMLIMIT_MIN ||
        header->password_slot.memlimit > PV_V1_PASSWORD_MEMLIMIT_MAX ||
        header->body_ciphertext_len < UINT64_C(4096) + PV_BODY_TAG_BYTES ||
        (header->body_ciphertext_len - PV_BODY_TAG_BYTES) % UINT64_C(4096) != 0U ||
        header->body_ciphertext_len > maximum_ciphertext) {
        sodium_memzero(header, sizeof(*header));
        return PV_ERR_FORMAT;
    }
    return PV_OK;
}

static pv_status secure_key_alloc(uint8_t **const key, const size_t len)
{
    *key = sodium_malloc(len);
    if (*key == NULL) {
        return PV_ERR_NOMEM;
    }
    if (sodium_mlock(*key, len) != 0) {
        sodium_free(*key);
        *key = NULL;
        return PV_ERR_SECURE_MEMORY;
    }
    return PV_OK;
}

static pv_status password_key(
    const pv_keyslot_password *const slot,
    const uint8_t *const password,
    const size_t password_len,
    uint8_t key[PV_WRAP_KEY_BYTES]
)
{
    if (slot == NULL || password == NULL || key == NULL || password_len == 0U ||
        password_len > crypto_pwhash_PASSWD_MAX ||
        slot->opslimit < PV_V1_PASSWORD_OPSLIMIT_MIN ||
        slot->opslimit > PV_V1_PASSWORD_OPSLIMIT_MAX ||
        slot->memlimit < PV_V1_PASSWORD_MEMLIMIT_MIN ||
        slot->memlimit > PV_V1_PASSWORD_MEMLIMIT_MAX) {
        return PV_ERR_AUTH;
    }
    if (crypto_pwhash(
            key,
            PV_WRAP_KEY_BYTES,
            (const char *)password,
            (unsigned long long)password_len,
            slot->salt,
            slot->opslimit,
            (size_t)slot->memlimit,
            crypto_pwhash_ALG_ARGON2ID13
        ) != 0) {
        return PV_ERR_SECURE_MEMORY;
    }
    return PV_OK;
}

static pv_status recovery_wrap_key(
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    uint8_t wrap_key[PV_WRAP_KEY_BYTES]
)
{
    if (crypto_kdf_derive_from_key(
            wrap_key,
            PV_WRAP_KEY_BYTES,
            0U,
            recovery_kdf_context,
            recovery_key
        ) != 0) {
        return PV_ERR_STATE;
    }
    return PV_OK;
}

static pv_status body_key(
    const uint8_t vmk[PV_WRAP_KEY_BYTES],
    uint8_t key[PV_BODY_KEY_BYTES]
)
{
    if (crypto_kdf_derive_from_key(key, PV_BODY_KEY_BYTES, 1U, body_kdf_context, vmk) != 0) {
        return PV_ERR_STATE;
    }
    return PV_OK;
}

static pv_status wrap_vmk(
    const uint8_t *const aad,
    const size_t aad_len,
    const uint8_t nonce[PV_WRAP_NONCE_BYTES],
    const uint8_t key[PV_WRAP_KEY_BYTES],
    const uint8_t vmk[PV_WRAP_KEY_BYTES],
    uint8_t wrapped[PV_WRAPPED_VMK_BYTES]
)
{
    unsigned long long length = 0U;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            wrapped,
            &length,
            vmk,
            PV_WRAP_KEY_BYTES,
            aad,
            (unsigned long long)aad_len,
            NULL,
            nonce,
            key
        ) != 0 || length != PV_WRAPPED_VMK_BYTES) {
        return PV_ERR_STATE;
    }
    return PV_OK;
}

static pv_status unwrap_vmk(
    const uint8_t *const aad,
    const size_t aad_len,
    const uint8_t nonce[PV_WRAP_NONCE_BYTES],
    const uint8_t key[PV_WRAP_KEY_BYTES],
    const uint8_t wrapped[PV_WRAPPED_VMK_BYTES],
    uint8_t vmk[PV_WRAP_KEY_BYTES]
)
{
    unsigned long long length = 0U;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            vmk,
            &length,
            NULL,
            wrapped,
            PV_WRAPPED_VMK_BYTES,
            aad,
            (unsigned long long)aad_len,
            nonce,
            key
        ) != 0 || length != PV_WRAP_KEY_BYTES) {
        sodium_memzero(vmk, PV_WRAP_KEY_BYTES);
        return PV_ERR_AUTH;
    }
    return PV_OK;
}

pv_status pv_crypto_rewrap_password(
    pv_file_header *const header,
    const uint8_t *const new_password,
    const size_t new_password_len,
    const uint8_t vmk[PV_WRAP_KEY_BYTES]
)
{
    uint8_t serialized[PV_FILE_HEADER_LEN];
    uint8_t *key = NULL;
    pv_status status;

    if (header == NULL || new_password == NULL || vmk == NULL) {
        return PV_ERR_USAGE;
    }
    header->password_slot.opslimit = PV_V1_PASSWORD_OPSLIMIT;
    header->password_slot.memlimit = PV_V1_PASSWORD_MEMLIMIT;
    randombytes_buf(header->password_slot.salt, PV_SALT_BYTES);
    randombytes_buf(header->password_slot.nonce, PV_WRAP_NONCE_BYTES);
    status = secure_key_alloc(&key, PV_WRAP_KEY_BYTES);
    if (status != PV_OK) {
        return status;
    }
    status = password_key(&header->password_slot, new_password, new_password_len, key);
    if (status == PV_OK) {
        status = pv_header_encode(header, serialized);
    }
    if (status == PV_OK) {
        status = wrap_vmk(
            serialized,
            PV_PASSWORD_AAD_LEN,
            header->password_slot.nonce,
            key,
            vmk,
            header->password_slot.wrapped_vmk
        );
    }
    sodium_free(key);
    sodium_memzero(serialized, sizeof(serialized));
    return status;
}

pv_status pv_crypto_rewrap_recovery(
    pv_file_header *const header,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    const uint8_t vmk[PV_WRAP_KEY_BYTES]
)
{
    uint8_t serialized[PV_FILE_HEADER_LEN];
    uint8_t *key = NULL;
    pv_status status;

    if (header == NULL || recovery_key == NULL || vmk == NULL) {
        return PV_ERR_USAGE;
    }
    randombytes_buf(header->recovery_slot.nonce, PV_WRAP_NONCE_BYTES);
    status = secure_key_alloc(&key, PV_WRAP_KEY_BYTES);
    if (status != PV_OK) {
        return status;
    }
    status = recovery_wrap_key(recovery_key, key);
    if (status == PV_OK) {
        status = pv_header_encode(header, serialized);
    }
    if (status == PV_OK) {
        status = wrap_vmk(
            serialized,
            PV_RECOVERY_AAD_LEN,
            header->recovery_slot.nonce,
            key,
            vmk,
            header->recovery_slot.wrapped_vmk
        );
    }
    sodium_free(key);
    sodium_memzero(serialized, sizeof(serialized));
    return status;
}

pv_status pv_crypto_create_header(
    pv_file_header *const header,
    const uint8_t *const password,
    const size_t password_len,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    const uint8_t vmk[PV_WRAP_KEY_BYTES]
)
{
    uint8_t requested_id[PV_VAULT_ID_BYTES];
    bool has_requested_id = false;
    size_t i;
    pv_status status;

    if (header == NULL || password == NULL || recovery_key == NULL || vmk == NULL) {
        return PV_ERR_USAGE;
    }
    memcpy(requested_id, header->vault_id, sizeof(requested_id));
    for (i = 0U; i < sizeof(requested_id); ++i) {
        has_requested_id = has_requested_id || requested_id[i] != 0U;
    }
    sodium_memzero(header, sizeof(*header));
    memcpy(header->magic, pv_magic, PV_MAGIC_LEN);
    header->major = PV_FILE_MAJOR;
    header->minor = PV_FILE_MINOR;
    header->header_len = PV_FILE_HEADER_LEN;
    header->kdf_id = PV_KDF_ARGON2ID13;
    header->wrap_aead_id = PV_AEAD_XCHACHA20POLY1305;
    header->body_aead_id = PV_AEAD_XCHACHA20POLY1305;
    header->slot_count = 2U;
    if (has_requested_id) {
        memcpy(header->vault_id, requested_id, sizeof(requested_id));
    } else {
        randombytes_buf(header->vault_id, sizeof(header->vault_id));
    }
    status = pv_crypto_rewrap_password(header, password, password_len, vmk);
    if (status == PV_OK) {
        status = pv_crypto_rewrap_recovery(header, recovery_key, vmk);
    }
    sodium_memzero(requested_id, sizeof(requested_id));
    return status;
}

pv_status pv_crypto_unlock_password(
    const pv_file_header *const header,
    const uint8_t *const password,
    const size_t password_len,
    uint8_t vmk[PV_WRAP_KEY_BYTES]
)
{
    uint8_t serialized[PV_FILE_HEADER_LEN];
    uint8_t *key = NULL;
    pv_status status;

    if (header == NULL || password == NULL || vmk == NULL) {
        return PV_ERR_USAGE;
    }
    status = secure_key_alloc(&key, PV_WRAP_KEY_BYTES);
    if (status != PV_OK) {
        return status;
    }
    status = password_key(&header->password_slot, password, password_len, key);
    if (status == PV_OK) {
        status = pv_header_encode(header, serialized);
    }
    if (status == PV_OK) {
        status = unwrap_vmk(
            serialized,
            PV_PASSWORD_AAD_LEN,
            header->password_slot.nonce,
            key,
            header->password_slot.wrapped_vmk,
            vmk
        );
    }
    sodium_free(key);
    sodium_memzero(serialized, sizeof(serialized));
    return status;
}

pv_status pv_crypto_unlock_recovery(
    const pv_file_header *const header,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    uint8_t vmk[PV_WRAP_KEY_BYTES]
)
{
    uint8_t serialized[PV_FILE_HEADER_LEN];
    uint8_t *key = NULL;
    pv_status status;

    if (header == NULL || recovery_key == NULL || vmk == NULL) {
        return PV_ERR_USAGE;
    }
    status = secure_key_alloc(&key, PV_WRAP_KEY_BYTES);
    if (status != PV_OK) {
        return status;
    }
    status = recovery_wrap_key(recovery_key, key);
    if (status == PV_OK) {
        status = pv_header_encode(header, serialized);
    }
    if (status == PV_OK) {
        status = unwrap_vmk(
            serialized,
            PV_RECOVERY_AAD_LEN,
            header->recovery_slot.nonce,
            key,
            header->recovery_slot.wrapped_vmk,
            vmk
        );
    }
    sodium_free(key);
    sodium_memzero(serialized, sizeof(serialized));
    return status;
}

pv_status pv_crypto_encrypt_body(
    pv_file_header *const header,
    const uint8_t vmk[PV_WRAP_KEY_BYTES],
    const uint8_t *const plaintext,
    const size_t plaintext_len,
    pv_buffer *const ciphertext
)
{
    uint8_t serialized[PV_FILE_HEADER_LEN];
    uint8_t *key = NULL;
    uint8_t *padded = NULL;
    size_t raw_len;
    size_t padded_len;
    unsigned long long output_len = 0U;
    pv_status status;

    if (header == NULL || vmk == NULL || plaintext == NULL || plaintext_len == 0U || ciphertext == NULL) {
        return PV_ERR_USAGE;
    }
    ciphertext->data = NULL;
    ciphertext->len = 0U;
    ciphertext->secure = false;
    if (!pv_size_add(plaintext_len, 4U, &raw_len) || raw_len > PV_MAX_PLAINTEXT) {
        return PV_ERR_LIMIT;
    }
    padded_len = (raw_len + 4095U) & ~((size_t)4095U);
    if (padded_len == 0U || padded_len > PV_MAX_PLAINTEXT) {
        return PV_ERR_LIMIT;
    }
    status = secure_key_alloc(&key, PV_BODY_KEY_BYTES);
    if (status != PV_OK) {
        return status;
    }
    status = body_key(vmk, key);
    if (status != PV_OK) {
        sodium_free(key);
        return status;
    }
    padded = sodium_malloc(padded_len);
    ciphertext->data = malloc(padded_len + PV_BODY_TAG_BYTES);
    if (padded == NULL || ciphertext->data == NULL || sodium_mlock(padded, padded_len) != 0) {
        sodium_free(padded);
        free(ciphertext->data);
        ciphertext->data = NULL;
        sodium_free(key);
        return PV_ERR_SECURE_MEMORY;
    }
    put_u32_le(padded, (uint32_t)plaintext_len);
    memcpy(padded + 4U, plaintext, plaintext_len);
    if (padded_len > raw_len) {
        randombytes_buf(padded + raw_len, padded_len - raw_len);
    }
    randombytes_buf(header->body_nonce, PV_WRAP_NONCE_BYTES);
    header->body_ciphertext_len = (uint64_t)padded_len + PV_BODY_TAG_BYTES;
    status = pv_header_encode(header, serialized);
    if (status == PV_OK && crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext->data,
            &output_len,
            padded,
            (unsigned long long)padded_len,
            serialized,
            PV_FILE_HEADER_LEN,
            NULL,
            header->body_nonce,
            key
        ) != 0) {
        status = PV_ERR_STATE;
    }
    if (status == PV_OK && output_len != header->body_ciphertext_len) {
        status = PV_ERR_STATE;
    }
    sodium_free(padded);
    sodium_free(key);
    sodium_memzero(serialized, sizeof(serialized));
    if (status != PV_OK) {
        pv_buffer_secure_free(ciphertext);
        return status;
    }
    ciphertext->len = (size_t)output_len;
    return PV_OK;
}

pv_status pv_crypto_decrypt_body(
    const pv_file_header *const header,
    const uint8_t vmk[PV_WRAP_KEY_BYTES],
    const uint8_t *const ciphertext,
    const size_t ciphertext_len,
    pv_buffer *const plaintext
)
{
    uint8_t serialized[PV_FILE_HEADER_LEN];
    uint8_t *key = NULL;
    unsigned long long decoded_len = 0U;
    uint32_t content_len;
    pv_status status;

    if (header == NULL || vmk == NULL || ciphertext == NULL || plaintext == NULL ||
        ciphertext_len != header->body_ciphertext_len ||
        ciphertext_len < 4096U + PV_BODY_TAG_BYTES ||
        (ciphertext_len - PV_BODY_TAG_BYTES) % 4096U != 0U) {
        return PV_ERR_FORMAT;
    }
    plaintext->data = NULL;
    plaintext->len = 0U;
    plaintext->secure = true;
    status = secure_key_alloc(&key, PV_BODY_KEY_BYTES);
    if (status != PV_OK) {
        return status;
    }
    status = body_key(vmk, key);
    if (status == PV_OK) {
        status = pv_header_encode(header, serialized);
    }
    plaintext->data = sodium_malloc(ciphertext_len - PV_BODY_TAG_BYTES);
    if (status != PV_OK || plaintext->data == NULL ||
        sodium_mlock(plaintext->data, ciphertext_len - PV_BODY_TAG_BYTES) != 0) {
        sodium_free(plaintext->data);
        plaintext->data = NULL;
        sodium_free(key);
        sodium_memzero(serialized, sizeof(serialized));
        return status == PV_OK ? PV_ERR_SECURE_MEMORY : status;
    }
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext->data,
            &decoded_len,
            NULL,
            ciphertext,
            (unsigned long long)ciphertext_len,
            serialized,
            PV_FILE_HEADER_LEN,
            header->body_nonce,
            key
        ) != 0) {
        pv_buffer_secure_free(plaintext);
        sodium_free(key);
        sodium_memzero(serialized, sizeof(serialized));
        return PV_ERR_AUTH;
    }
    sodium_free(key);
    sodium_memzero(serialized, sizeof(serialized));
    if (decoded_len < 4U || decoded_len > PV_MAX_PLAINTEXT || decoded_len % 4096U != 0U) {
        pv_buffer_secure_free(plaintext);
        return PV_ERR_FORMAT;
    }
    content_len = get_u32_le(plaintext->data);
    if ((uint64_t)content_len > decoded_len - 4U || content_len == 0U) {
        pv_buffer_secure_free(plaintext);
        return PV_ERR_FORMAT;
    }
    memmove(plaintext->data, plaintext->data + 4U, content_len);
    sodium_memzero(plaintext->data + content_len, (size_t)decoded_len - content_len);
    plaintext->len = content_len;
    return PV_OK;
}
