#include "pvault_internal.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char crockford_alphabet[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#define PV_RECOVERY_FILE_MAX 1024U

typedef struct recovery_hash_workspace {
    crypto_generichash_state state;
    uint8_t digest[crypto_generichash_BYTES];
} recovery_hash_workspace;

static void *recovery_secure_alloc(const size_t length)
{
    void *const memory = sodium_malloc(length);

    if (memory == NULL) {
        return NULL;
    }
    if (sodium_mlock(memory, length) != 0) {
        sodium_free(memory);
        return NULL;
    }
    sodium_memzero(memory, length);
    return memory;
}

static pv_status recovery_checksum(
    const uint8_t vault_id[PV_VAULT_ID_BYTES],
    const uint8_t key[PV_RECOVERY_KEY_BYTES],
    uint8_t checksum[PV_RECOVERY_CHECKSUM_BYTES]
)
{
    recovery_hash_workspace *workspace;
    pv_status status = PV_OK;

    workspace = recovery_secure_alloc(sizeof(*workspace));
    if (workspace == NULL) {
        return PV_ERR_SECURE_MEMORY;
    }
    if (crypto_generichash_init(&workspace->state, NULL, 0U, sizeof(workspace->digest)) != 0 ||
        crypto_generichash_update(&workspace->state, vault_id, PV_VAULT_ID_BYTES) != 0 ||
        crypto_generichash_update(&workspace->state, key, PV_RECOVERY_KEY_BYTES) != 0 ||
        crypto_generichash_final(&workspace->state, workspace->digest, sizeof(workspace->digest)) != 0) {
        status = PV_ERR_STATE;
    }
    if (status == PV_OK) {
        memcpy(checksum, workspace->digest, PV_RECOVERY_CHECKSUM_BYTES);
    }
    sodium_free(workspace);
    return status;
}

static size_t base32_encode(const uint8_t *const input, const size_t input_len, char *const output, const size_t cap)
{
    uint32_t buffer = 0U;
    unsigned bits = 0U;
    size_t in_pos = 0U;
    size_t out_pos = 0U;

    while (in_pos < input_len || bits > 0U) {
        if (bits < 5U && in_pos < input_len) {
            buffer = (buffer << 8U) | input[in_pos++];
            bits += 8U;
        }
        if (bits < 5U) {
            buffer <<= 5U - bits;
            bits = 5U;
        }
        if (out_pos + 1U >= cap) {
            return 0U;
        }
        bits -= 5U;
        output[out_pos++] = crockford_alphabet[(buffer >> bits) & 31U];
        if (bits == 0U) {
            buffer = 0U;
        } else {
            buffer &= (UINT32_C(1) << bits) - 1U;
        }
    }
    output[out_pos] = '\0';
    return out_pos;
}

static int crockford_value(const int c)
{
    const int upper = toupper(c);
    const char *found;

    if (upper == 'O') {
        return 0;
    }
    if (upper == 'I' || upper == 'L') {
        return 1;
    }
    found = strchr(crockford_alphabet, upper);
    return found == NULL ? -1 : (int)(found - crockford_alphabet);
}

static bool base32_decode(const char *const input, uint8_t *const output, const size_t output_len)
{
    uint32_t buffer = 0U;
    unsigned bits = 0U;
    size_t out_pos = 0U;
    const char *cursor = input;

    while (*cursor != '\0') {
        const int value = crockford_value((unsigned char)*cursor++);
        if (value < 0) {
            return false;
        }
        buffer = (buffer << 5U) | (uint32_t)value;
        bits += 5U;
        if (bits >= 8U) {
            bits -= 8U;
            if (out_pos >= output_len) {
                return false;
            }
            output[out_pos++] = (uint8_t)(buffer >> bits);
            if (bits == 0U) {
                buffer = 0U;
            } else {
                buffer &= (UINT32_C(1) << bits) - 1U;
            }
        }
    }
    return out_pos == output_len && (bits == 0U || buffer == 0U);
}

pv_status pv_recovery_encode(
    const uint8_t vault_id[PV_VAULT_ID_BYTES],
    const uint8_t key[PV_RECOVERY_KEY_BYTES],
    char *const encoded,
    const size_t encoded_len
)
{
    uint8_t *material = NULL;
    char *raw = NULL;
    size_t raw_len;
    size_t out_pos = 0U;
    size_t i;
    pv_status status;

    if (vault_id == NULL || key == NULL || encoded == NULL || encoded_len < 16U) {
        return PV_ERR_USAGE;
    }
    encoded[0] = '\0';
    material = recovery_secure_alloc(PV_RECOVERY_KEY_BYTES + PV_RECOVERY_CHECKSUM_BYTES);
    raw = recovery_secure_alloc(80U);
    if (material == NULL || raw == NULL) {
        sodium_free(material);
        sodium_free(raw);
        return PV_ERR_SECURE_MEMORY;
    }
    memcpy(material, key, PV_RECOVERY_KEY_BYTES);
    status = recovery_checksum(vault_id, key, material + PV_RECOVERY_KEY_BYTES);
    if (status != PV_OK) {
        sodium_free(material);
        sodium_free(raw);
        return status;
    }
    raw_len = base32_encode(
        material,
        PV_RECOVERY_KEY_BYTES + PV_RECOVERY_CHECKSUM_BYTES,
        raw,
        80U
    );
    sodium_free(material);
    if (raw_len == 0U) {
        sodium_free(raw);
        return PV_ERR_LIMIT;
    }
    if (encoded_len <= 5U + raw_len + raw_len / 5U) {
        sodium_free(raw);
        return PV_ERR_LIMIT;
    }
    memcpy(encoded, "PV1R-", 5U);
    out_pos = 5U;
    for (i = 0U; i < raw_len; ++i) {
        if (i > 0U && i % 5U == 0U) {
            encoded[out_pos++] = '-';
        }
        encoded[out_pos++] = raw[i];
    }
    encoded[out_pos] = '\0';
    sodium_free(raw);
    return PV_OK;
}

pv_status pv_recovery_generate(
    const uint8_t vault_id[PV_VAULT_ID_BYTES],
    uint8_t key[PV_RECOVERY_KEY_BYTES],
    char *const encoded,
    const size_t encoded_len
)
{
    if (vault_id == NULL || key == NULL || encoded == NULL) {
        return PV_ERR_USAGE;
    }
    randombytes_buf(key, PV_RECOVERY_KEY_BYTES);
    return pv_recovery_encode(vault_id, key, encoded, encoded_len);
}

pv_status pv_recovery_decode(
    const char *const encoded,
    const uint8_t vault_id[PV_VAULT_ID_BYTES],
    uint8_t key[PV_RECOVERY_KEY_BYTES]
)
{
    char *normalized = NULL;
    uint8_t *material = NULL;
    uint8_t expected[PV_RECOVERY_CHECKSUM_BYTES];
    size_t pos = 0U;
    const char *cursor;
    pv_status status;

    if (encoded == NULL || vault_id == NULL || key == NULL) {
        return PV_ERR_USAGE;
    }
    sodium_memzero(key, PV_RECOVERY_KEY_BYTES);
    cursor = encoded;
    while (isspace((unsigned char)*cursor) != 0) {
        ++cursor;
    }
    if (strncasecmp(cursor, "PV1R", 4U) != 0) {
        return PV_ERR_AUTH;
    }
    normalized = recovery_secure_alloc(80U);
    material = recovery_secure_alloc(PV_RECOVERY_KEY_BYTES + PV_RECOVERY_CHECKSUM_BYTES);
    if (normalized == NULL || material == NULL) {
        sodium_free(normalized);
        sodium_free(material);
        return PV_ERR_SECURE_MEMORY;
    }
    cursor += 4;
    while (*cursor != '\0') {
        if (*cursor != '-' && isspace((unsigned char)*cursor) == 0) {
            if (pos + 1U >= 80U) {
                status = PV_ERR_AUTH;
                goto cleanup;
            }
            normalized[pos++] = (char)toupper((unsigned char)*cursor);
        }
        ++cursor;
    }
    normalized[pos] = '\0';
    if (!base32_decode(
            normalized,
            material,
            PV_RECOVERY_KEY_BYTES + PV_RECOVERY_CHECKSUM_BYTES
        )) {
        status = PV_ERR_AUTH;
        goto cleanup;
    }
    memcpy(key, material, PV_RECOVERY_KEY_BYTES);
    status = recovery_checksum(vault_id, key, expected);
    if (status != PV_OK ||
        sodium_memcmp(expected, material + PV_RECOVERY_KEY_BYTES, PV_RECOVERY_CHECKSUM_BYTES) != 0) {
        sodium_memzero(key, PV_RECOVERY_KEY_BYTES);
        status = PV_ERR_AUTH;
    }
cleanup:
    sodium_memzero(expected, sizeof(expected));
    sodium_free(material);
    sodium_free(normalized);
    return status;
}

static pv_status write_all(const int fd, const void *const data, const size_t len)
{
    const uint8_t *cursor = data;
    size_t remaining = len;

    while (remaining > 0U) {
        const ssize_t written = write(fd, cursor, remaining);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return PV_ERR_IO;
        }
        cursor += (size_t)written;
        remaining -= (size_t)written;
    }
    return PV_OK;
}

static pv_status fsync_parent_path(const char *const path)
{
    char scratch[PATH_MAX];
    char *parent;
    struct stat info;
    int fd;
    pv_status status = PV_OK;

    if (path == NULL || strlen(path) >= sizeof(scratch)) return PV_ERR_LIMIT;
    (void)strcpy(scratch, path);
    parent = dirname(scratch);
    fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &info) != 0 || !S_ISDIR(info.st_mode) ||
        info.st_uid != geteuid() || (info.st_mode & 0022) != 0 || fsync(fd) != 0) {
        status = PV_ERR_IO;
    }
    if (fd >= 0 && close(fd) != 0 && status == PV_OK) status = PV_ERR_IO;
    return status;
}

pv_status pv_recovery_write_file(
    const char *const path,
    const char *const encoded,
    const uint8_t vault_id[PV_VAULT_ID_BYTES]
)
{
    int fd;
    char id_hex[PV_VAULT_ID_BYTES * 2U + 1U];
    char *content;
    int length;
    pv_status status;

    if (path == NULL || encoded == NULL || vault_id == NULL) {
        return PV_ERR_USAGE;
    }
    status = fsync_parent_path(path);
    if (status != PV_OK) return status;
    content = recovery_secure_alloc(512U);
    if (content == NULL) {
        return PV_ERR_SECURE_MEMORY;
    }
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        status = errno == EEXIST ? PV_ERR_EXISTS : PV_ERR_IO;
        sodium_free(content);
        return status;
    }
    pv_hex_encode(vault_id, PV_VAULT_ID_BYTES, id_hex, sizeof(id_hex));
    length = snprintf(
        content,
        512U,
        "PVault recovery key v1\nVault: %s\n\n%s\n\nKeep this file offline and separate from the vault.\n",
        id_hex,
        encoded
    );
    if (length < 0 || (size_t)length >= 512U) {
        (void)close(fd);
        (void)unlink(path);
        sodium_free(content);
        return PV_ERR_LIMIT;
    }
    status = write_all(fd, content, (size_t)length);
    if (status == PV_OK && fsync(fd) != 0) {
        status = PV_ERR_IO;
    }
    if (close(fd) != 0 && status == PV_OK) {
        status = PV_ERR_IO;
    }
    if (status == PV_OK) {
        status = fsync_parent_path(path);
    }
    sodium_free(content);
    if (status != PV_OK) {
        (void)unlink(path);
        (void)fsync_parent_path(path);
    }
    return status;
}

pv_status pv_recovery_read_file(const char *const path, char *const encoded, const size_t encoded_len)
{
    uint8_t *content;
    size_t used = 0U;
    size_t position = 0U;
    int fd;
    struct stat info;
    pv_status status = PV_ERR_FORMAT;

    if (path == NULL || encoded == NULL || encoded_len == 0U) {
        return PV_ERR_USAGE;
    }
    encoded[0] = '\0';
    content = recovery_secure_alloc(PV_RECOVERY_FILE_MAX + 1U);
    if (content == NULL) {
        return PV_ERR_SECURE_MEMORY;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        sodium_free(content);
        return PV_ERR_IO;
    }
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != geteuid() ||
        info.st_nlink != 1 || (info.st_mode & 0077) != 0) {
        status = PV_ERR_IO;
        goto cleanup;
    }
    while (used < PV_RECOVERY_FILE_MAX + 1U) {
        ssize_t received;

        do {
            received = read(fd, content + used, PV_RECOVERY_FILE_MAX + 1U - used);
        } while (received < 0 && errno == EINTR);
        if (received < 0) {
            status = PV_ERR_IO;
            goto cleanup;
        }
        if (received == 0) {
            break;
        }
        used += (size_t)received;
    }
    if (used > PV_RECOVERY_FILE_MAX) {
        status = PV_ERR_LIMIT;
        goto cleanup;
    }
    while (position < used) {
        const size_t line_start = position;
        size_t line_len;

        while (position < used && content[position] != (uint8_t)'\n') {
            ++position;
        }
        line_len = position - line_start;
        if (line_len > 0U && content[line_start + line_len - 1U] == (uint8_t)'\r') {
            --line_len;
        }
        if (line_len >= 4U && strncasecmp((const char *)content + line_start, "PV1R", 4U) == 0) {
            if (line_len >= encoded_len) {
                status = PV_ERR_LIMIT;
                goto cleanup;
            }
            memcpy(encoded, content + line_start, line_len);
            encoded[line_len] = '\0';
            status = PV_OK;
            goto cleanup;
        }
        if (position < used) {
            ++position;
        }
    }

cleanup:
    if (close(fd) != 0 && status == PV_OK) {
        status = PV_ERR_IO;
    }
    sodium_free(content);
    return status;
}
