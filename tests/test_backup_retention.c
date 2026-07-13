#define _POSIX_C_SOURCE 200809L

#include "test.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PV_AUTO_BACKUP_NAME_LENGTH 67U

static const uint8_t retention_password[] = "retention-master-password";

static const uint8_t legacy_bytes[] = {
    0x00U, 'l', 'e', 'g', 'a', 'c', 'y', 0xffU
};
static const uint8_t manual_bytes[] = {
    0x01U, 'm', 'a', 'n', 'u', 'a', 'l', 0xfeU
};
static const uint8_t pre_restore_bytes[] = {
    0x02U, 'p', 'r', 'e', '-', 'r', 'e', 's', 't', 'o', 'r', 'e', 0xfdU
};
static const uint8_t pre_migrate_bytes[] = {
    0x03U, 'p', 'r', 'e', '-', 'm', 'i', 'g', 'r', 'a', 't', 'e', 0xfcU
};
static const uint8_t other_vault_bytes[] = {
    0x04U, 'o', 't', 'h', 'e', 'r', '-', 'v', 'a', 'u', 'l', 't', 0xfbU
};
static const uint8_t near_match_bytes[] = {
    0x05U, 'n', 'e', 'a', 'r', '-', 'm', 'a', 't', 'c', 'h', 0xfaU
};
static const uint8_t symlink_target_bytes[] = {
    0x06U, 's', 'y', 'm', 'l', 'i', 'n', 'k', 0xf9U
};
static const uint8_t unsafe_candidate_bytes[] = {
    0x07U, 'u', 'n', 's', 'a', 'f', 'e', 0xf8U
};
static const uint8_t collision_bytes[] = {
    0x08U, 'c', 'o', 'l', 'l', 'i', 's', 'i', 'o', 'n', 0xf7U
};

typedef struct retention_fixture {
    char path[PATH_MAX];
    const uint8_t *bytes;
    size_t length;
} retention_fixture;

void pv_test_backup_retention_suite(void);

static bool retention_make_path(
    char *const output,
    const size_t output_len,
    const char *const directory,
    const char *const name
)
{
    const int written = snprintf(output, output_len, "%s/%s", directory, name);

    return written > 0 && (size_t)written < output_len;
}

static void retention_fill_recovery_key(
    uint8_t key[PV_RECOVERY_KEY_BYTES],
    const uint8_t seed
)
{
    size_t index;

    for (index = 0U; index < PV_RECOVERY_KEY_BYTES; ++index) {
        key[index] = (uint8_t)(seed + (uint8_t)index);
    }
}

static bool retention_write_all(
    const int fd,
    const uint8_t *const bytes,
    const size_t length
)
{
    size_t offset = 0U;

    while (offset < length) {
        const ssize_t written = write(fd, bytes + offset, length - offset);

        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        offset += (size_t)written;
    }
    return true;
}

static bool retention_write_fixture(
    const char *const path,
    const uint8_t *const bytes,
    const size_t length
)
{
    int fd;
    bool success;

    fd = open(
        path,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0600
    );
    if (fd < 0) {
        return false;
    }
    success = retention_write_all(fd, bytes, length) && fsync(fd) == 0;
    if (close(fd) != 0) {
        success = false;
    }
    return success;
}

static bool retention_file_equals(
    const char *const path,
    const uint8_t *const expected,
    const size_t expected_len
)
{
    uint8_t buffer[128];
    size_t offset = 0U;
    int fd;
    bool success = true;

    if (expected_len > sizeof buffer) {
        return false;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return false;
    }
    while (offset < expected_len) {
        const ssize_t got = read(fd, buffer + offset, expected_len - offset);

        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            success = false;
            break;
        }
        offset += (size_t)got;
    }
    if (success) {
        uint8_t extra = 0U;
        ssize_t got;

        do {
            got = read(fd, &extra, 1U);
        } while (got < 0 && errno == EINTR);
        success = got == 0 && offset == expected_len &&
            sodium_memcmp(buffer, expected, expected_len) == 0;
    }
    if (close(fd) != 0) {
        success = false;
    }
    sodium_memzero(buffer, sizeof buffer);
    return success;
}

static bool retention_read_exact_fd(
    const int fd,
    uint8_t *const output,
    const size_t length
)
{
    size_t offset = 0U;

    while (offset < length) {
        const ssize_t got = read(fd, output + offset, length - offset);

        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            return false;
        }
        offset += (size_t)got;
    }
    return true;
}

static bool retention_files_equal(
    const char *const left_path,
    const char *const right_path
)
{
    uint8_t left_buffer[4096];
    uint8_t right_buffer[4096];
    struct stat left_stat;
    struct stat right_stat;
    off_t remaining;
    int left_fd = -1;
    int right_fd = -1;
    bool equal = false;

    left_fd = open(left_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    right_fd = open(right_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (left_fd < 0 || right_fd < 0 || fstat(left_fd, &left_stat) != 0 ||
        fstat(right_fd, &right_stat) != 0 || !S_ISREG(left_stat.st_mode) ||
        !S_ISREG(right_stat.st_mode) || left_stat.st_size < 0 ||
        left_stat.st_size != right_stat.st_size) {
        goto cleanup;
    }
    remaining = left_stat.st_size;
    while (remaining > 0) {
        const size_t chunk = remaining > (off_t)sizeof left_buffer
            ? sizeof left_buffer
            : (size_t)remaining;

        if (!retention_read_exact_fd(left_fd, left_buffer, chunk) ||
            !retention_read_exact_fd(right_fd, right_buffer, chunk) ||
            sodium_memcmp(left_buffer, right_buffer, chunk) != 0) {
            goto cleanup;
        }
        remaining -= (off_t)chunk;
    }
    equal = true;

cleanup:
    if (left_fd >= 0 && close(left_fd) != 0) {
        equal = false;
    }
    if (right_fd >= 0 && close(right_fd) != 0) {
        equal = false;
    }
    sodium_memzero(left_buffer, sizeof left_buffer);
    sodium_memzero(right_buffer, sizeof right_buffer);
    return equal;
}

static bool retention_directory_has_temporary(const char *const path)
{
    DIR *stream;
    struct dirent *entry;
    bool found = false;

    stream = opendir(path);
    if (stream == NULL) {
        return true;
    }
    while ((entry = readdir(stream)) != NULL) {
        if (strstr(entry->d_name, ".tmp.") != NULL) {
            found = true;
            break;
        }
    }
    if (closedir(stream) != 0) {
        return true;
    }
    return found;
}

static bool retention_hash_file(
    const char *const path,
    uint8_t digest[crypto_generichash_BYTES]
)
{
    crypto_generichash_state state;
    uint8_t buffer[4096];
    int fd;
    bool success = true;

    sodium_memzero(digest, crypto_generichash_BYTES);
    sodium_memzero(&state, sizeof state);
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return false;
    }
    if (crypto_generichash_init(
            &state,
            NULL,
            0U,
            crypto_generichash_BYTES
        ) != 0) {
        (void)close(fd);
        return false;
    }
    for (;;) {
        ssize_t got;

        do {
            got = read(fd, buffer, sizeof buffer);
        } while (got < 0 && errno == EINTR);
        if (got < 0) {
            success = false;
            break;
        }
        if (got == 0) {
            break;
        }
        if (crypto_generichash_update(&state, buffer, (size_t)got) != 0) {
            success = false;
            break;
        }
    }
    if (success && crypto_generichash_final(
            &state,
            digest,
            crypto_generichash_BYTES
        ) != 0) {
        success = false;
    }
    if (close(fd) != 0) {
        success = false;
    }
    sodium_memzero(&state, sizeof state);
    sodium_memzero(buffer, sizeof buffer);
    if (!success) {
        sodium_memzero(digest, crypto_generichash_BYTES);
    }
    return success;
}

static bool retention_flip_last_byte(const char *const path)
{
    uint8_t byte = 0U;
    off_t offset;
    int fd;
    bool success = false;

    fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return false;
    }
    offset = lseek(fd, -1, SEEK_END);
    if (offset >= 0 && pread(fd, &byte, 1U, offset) == 1) {
        byte ^= 0x80U;
        success = pwrite(fd, &byte, 1U, offset) == 1 && fsync(fd) == 0;
    }
    sodium_memzero(&byte, sizeof byte);
    if (close(fd) != 0) {
        success = false;
    }
    return success;
}

static bool retention_header_has_vault_id(
    const char *const path,
    const uint8_t vault_id[PV_VAULT_ID_BYTES]
)
{
    uint8_t bytes[PV_FILE_HEADER_LEN];
    pv_file_header header;
    size_t offset = 0U;
    int fd;
    pv_status status = PV_ERR_IO;

    sodium_memzero(bytes, sizeof bytes);
    sodium_memzero(&header, sizeof header);
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return false;
    }
    while (offset < sizeof bytes) {
        const ssize_t got = read(fd, bytes + offset, sizeof bytes - offset);

        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            break;
        }
        offset += (size_t)got;
    }
    if (offset == sizeof bytes) {
        status = pv_header_decode(bytes, &header);
    }
    if (close(fd) != 0) {
        status = PV_ERR_IO;
    }
    if (status == PV_OK && sodium_memcmp(
            header.vault_id,
            vault_id,
            PV_VAULT_ID_BYTES
        ) != 0) {
        status = PV_ERR_FORMAT;
    }
    sodium_memzero(&header, sizeof header);
    sodium_memzero(bytes, sizeof bytes);
    return status == PV_OK;
}

static bool retention_auto_name(
    char *const output,
    const size_t output_len,
    const uint8_t vault_id[PV_VAULT_ID_BYTES],
    const uint64_t generation
)
{
    char id_hex[PV_VAULT_ID_BYTES * 2U + 1U];
    int written;

    pv_hex_encode(vault_id, PV_VAULT_ID_BYTES, id_hex, sizeof id_hex);
    written = snprintf(
        output,
        output_len,
        "auto-v1-%s-g%020llu.pvlt",
        id_hex,
        (unsigned long long)generation
    );
    sodium_memzero(id_hex, sizeof id_hex);
    return written == (int)PV_AUTO_BACKUP_NAME_LENGTH &&
        (size_t)written < output_len;
}

static bool retention_auto_path(
    char *const output,
    const size_t output_len,
    const char *const backup_directory,
    const uint8_t vault_id[PV_VAULT_ID_BYTES],
    const uint64_t generation
)
{
    char name[PV_AUTO_BACKUP_NAME_LENGTH + 1U];
    bool success;

    success = retention_auto_name(
        name,
        sizeof name,
        vault_id,
        generation
    ) && retention_make_path(output, output_len, backup_directory, name);
    sodium_memzero(name, sizeof name);
    return success;
}

static bool retention_near_match_path(
    char *const output,
    const size_t output_len,
    const char *const backup_directory,
    const uint8_t vault_id[PV_VAULT_ID_BYTES],
    const uint64_t generation
)
{
    char id_hex[PV_VAULT_ID_BYTES * 2U + 1U];
    char name[PV_AUTO_BACKUP_NAME_LENGTH + 1U];
    int written;
    bool success;

    pv_hex_encode(vault_id, PV_VAULT_ID_BYTES, id_hex, sizeof id_hex);
    written = snprintf(
        name,
        sizeof name,
        "auto-v1-%s-G%020llu.pvlt",
        id_hex,
        (unsigned long long)generation
    );
    success = written == (int)PV_AUTO_BACKUP_NAME_LENGTH &&
        retention_make_path(output, output_len, backup_directory, name);
    sodium_memzero(id_hex, sizeof id_hex);
    sodium_memzero(name, sizeof name);
    return success;
}

static bool retention_is_managed_auto_name(
    const char *const name,
    const uint8_t vault_id[PV_VAULT_ID_BYTES]
)
{
    char expected_prefix[8U + PV_VAULT_ID_BYTES * 2U + 2U + 1U];
    char id_hex[PV_VAULT_ID_BYTES * 2U + 1U];
    const size_t name_len = strlen(name);
    size_t index;
    int written;
    bool matches = true;

    pv_hex_encode(vault_id, PV_VAULT_ID_BYTES, id_hex, sizeof id_hex);
    written = snprintf(expected_prefix, sizeof expected_prefix, "auto-v1-%s-g", id_hex);
    if (written < 0 || (size_t)written + 20U + 5U != name_len ||
        name_len != PV_AUTO_BACKUP_NAME_LENGTH ||
        strncmp(name, expected_prefix, (size_t)(written < 0 ? 0 : written)) != 0 ||
        strcmp(name + name_len - 5U, ".pvlt") != 0) {
        matches = false;
    }
    if (matches) {
        for (index = (size_t)written; index < (size_t)written + 20U; ++index) {
            if (name[index] < '0' || name[index] > '9') {
                matches = false;
                break;
            }
        }
    }
    sodium_memzero(expected_prefix, sizeof expected_prefix);
    sodium_memzero(id_hex, sizeof id_hex);
    return matches;
}

static size_t retention_count_secure_managed(
    const char *const directory,
    const uint8_t vault_id[PV_VAULT_ID_BYTES]
)
{
    DIR *stream;
    struct dirent *entry;
    size_t count = 0U;

    stream = opendir(directory);
    if (stream == NULL) {
        return SIZE_MAX;
    }
    while ((entry = readdir(stream)) != NULL) {
        char path[PATH_MAX];
        struct stat info;

        if (!retention_is_managed_auto_name(entry->d_name, vault_id) ||
            !retention_make_path(path, sizeof path, directory, entry->d_name) ||
            lstat(path, &info) != 0) {
            continue;
        }
        if (S_ISREG(info.st_mode) && info.st_uid == geteuid() &&
            info.st_nlink == 1 && (info.st_mode & 0777U) == 0600U) {
            ++count;
        }
    }
    if (closedir(stream) != 0) {
        return SIZE_MAX;
    }
    return count;
}

static pv_status retention_add_record(
    pv_vault *const vault,
    const unsigned ordinal
)
{
    pv_record source;
    uint8_t title[32];
    uint8_t secret[32];
    int title_len;
    int secret_len;
    size_t index;
    pv_status status;

    sodium_memzero(&source, sizeof source);
    title_len = snprintf((char *)title, sizeof title, "retention-record-%u", ordinal);
    secret_len = snprintf((char *)secret, sizeof secret, "synthetic-secret-%u", ordinal);
    if (title_len <= 0 || (size_t)title_len >= sizeof title ||
        secret_len <= 0 || (size_t)secret_len >= sizeof secret) {
        sodium_memzero(title, sizeof title);
        sodium_memzero(secret, sizeof secret);
        return PV_ERR_LIMIT;
    }
    for (index = 0U; index < sizeof source.id; ++index) {
        source.id[index] = (uint8_t)(ordinal * 16U + (unsigned)index + 1U);
    }
    source.title = (pv_slice){title, (size_t)title_len};
    source.password = (pv_slice){secret, (size_t)secret_len};
    status = pv_model_add_record(vault, &source, NULL);
    sodium_memzero(&source, sizeof source);
    sodium_memzero(title, sizeof title);
    sodium_memzero(secret, sizeof secret);
    return status;
}

static bool retention_create_and_open(
    const char *const vault_path,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    pv_vault *const vault,
    pv_file_header *const header
)
{
    pv_vault created = {0};
    pv_status status;

    status = pv_store_create(
        vault_path,
        retention_password,
        sizeof retention_password - 1U,
        recovery_key,
        &created
    );
    PV_CHECK_STATUS(status, PV_OK);
    pv_model_destroy(&created);
    if (status != PV_OK) {
        return false;
    }
    status = pv_store_open_password(
        vault_path,
        retention_password,
        sizeof retention_password - 1U,
        vault,
        header
    );
    PV_CHECK_STATUS(status, PV_OK);
    return status == PV_OK;
}

static bool retention_snapshot_has_generation(
    const char *const path,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    const uint64_t generation,
    const size_t record_count
)
{
    pv_vault opened = {0};
    pv_file_header header = {0};
    const pv_status status = pv_store_open_recovery(
        path,
        recovery_key,
        &opened,
        &header
    );
    const bool valid = status == PV_OK && opened.generation == generation &&
        opened.record_count == record_count;

    pv_model_destroy(&opened);
    sodium_memzero(&header, sizeof header);
    return valid;
}

static bool retention_set_mtime(const char *const path, const time_t seconds)
{
    const struct timespec times[2] = {
        {.tv_sec = seconds, .tv_nsec = 0L},
        {.tv_sec = seconds, .tv_nsec = 0L}
    };

    return utimensat(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW) == 0;
}

static bool retention_readlink_equals(
    const char *const path,
    const char *const expected
)
{
    char target[PATH_MAX];
    const ssize_t length = readlink(path, target, sizeof target - 1U);

    if (length < 0 || (size_t)length >= sizeof target) {
        return false;
    }
    target[(size_t)length] = '\0';
    return strcmp(target, expected) == 0;
}

static void retention_keeps_owned_generations_and_private_snapshots(void)
{
    static const char *const fixed_names[] = {
        "00000000000000000001-00000000000000000001.pvlt",
        "manual-snapshot.pvlt",
        "pre-restore-00000000000000000001-deadbeef.pvlt",
        "pre-migrate-v1-to-v2-00000000000000000001.pvlt"
    };
    static const uint8_t *const fixed_bytes[] = {
        legacy_bytes,
        manual_bytes,
        pre_restore_bytes,
        pre_migrate_bytes
    };
    static const size_t fixed_lengths[] = {
        sizeof legacy_bytes,
        sizeof manual_bytes,
        sizeof pre_restore_bytes,
        sizeof pre_migrate_bytes
    };
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    uint8_t other_vault_id[PV_VAULT_ID_BYTES];
    char directory[PATH_MAX] = {0};
    char vault_path[PATH_MAX];
    char backup_directory[PATH_MAX];
    char expected_path[PATH_MAX];
    char symlink_path[PATH_MAX];
    char symlink_target_path[PATH_MAX];
    char unsafe_path[PATH_MAX];
    char unsafe_source_path[PATH_MAX];
    retention_fixture fixtures[6];
    pv_vault vault = {0};
    pv_file_header header = {0};
    uint64_t initial_generation;
    size_t fixture_count = 0U;
    size_t index;
    pv_status status = PV_OK;

#ifdef PVAULT_TEST_FAULT_INJECTION
    pv_store_test_fault_reset();
#endif
    retention_fill_recovery_key(recovery_key, 0x40U);
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        goto cleanup;
    }
    PV_CHECK(retention_make_path(vault_path, sizeof vault_path, directory, "vault.pvlt"));
    PV_CHECK(retention_make_path(
        backup_directory,
        sizeof backup_directory,
        directory,
        "backups"
    ));
    if (!retention_create_and_open(vault_path, recovery_key, &vault, &header)) {
        goto cleanup;
    }
    initial_generation = vault.generation;
    PV_CHECK(initial_generation == 1U);

    for (index = 1U; index <= 2U; ++index) {
        status = retention_add_record(&vault, (unsigned)index);
        PV_CHECK_STATUS(status, PV_OK);
        if (status == PV_OK) {
            status = pv_store_save(&vault, &header, 2U);
            PV_CHECK_STATUS(status, PV_OK);
        }
        if (status != PV_OK) {
            goto cleanup;
        }
    }

    for (index = 0U; index < sizeof fixed_names / sizeof fixed_names[0]; ++index) {
        retention_fixture *const fixture = &fixtures[fixture_count++];

        PV_CHECK(retention_make_path(
            fixture->path,
            sizeof fixture->path,
            backup_directory,
            fixed_names[index]
        ));
        fixture->bytes = fixed_bytes[index];
        fixture->length = fixed_lengths[index];
        PV_CHECK(retention_write_fixture(
            fixture->path,
            fixture->bytes,
            fixture->length
        ));
    }

    memcpy(other_vault_id, vault.vault_id, sizeof other_vault_id);
    other_vault_id[0] ^= 0x80U;
    {
        retention_fixture *const fixture = &fixtures[fixture_count++];

        PV_CHECK(retention_auto_path(
            fixture->path,
            sizeof fixture->path,
            backup_directory,
            other_vault_id,
            initial_generation + 20U
        ));
        fixture->bytes = other_vault_bytes;
        fixture->length = sizeof other_vault_bytes;
        PV_CHECK(retention_write_fixture(
            fixture->path,
            fixture->bytes,
            fixture->length
        ));
    }
    {
        retention_fixture *const fixture = &fixtures[fixture_count++];

        PV_CHECK(retention_near_match_path(
            fixture->path,
            sizeof fixture->path,
            backup_directory,
            vault.vault_id,
            initial_generation + 21U
        ));
        fixture->bytes = near_match_bytes;
        fixture->length = sizeof near_match_bytes;
        PV_CHECK(retention_write_fixture(
            fixture->path,
            fixture->bytes,
            fixture->length
        ));
    }

    status = retention_add_record(&vault, 3U);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        status = pv_store_save(&vault, &header, 2U);
        PV_CHECK_STATUS(status, PV_OK);
    }
    if (status != PV_OK) {
        goto cleanup;
    }

    PV_CHECK(retention_auto_path(
        expected_path,
        sizeof expected_path,
        backup_directory,
        vault.vault_id,
        initial_generation + 1U
    ));
    PV_CHECK(retention_set_mtime(expected_path, (time_t)2000000000));
    PV_CHECK(retention_auto_path(
        expected_path,
        sizeof expected_path,
        backup_directory,
        vault.vault_id,
        initial_generation + 2U
    ));
    PV_CHECK(retention_set_mtime(expected_path, (time_t)1000000000));

    status = retention_add_record(&vault, 4U);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        status = pv_store_save(&vault, &header, 2U);
        PV_CHECK_STATUS(status, PV_OK);
    }
    if (status != PV_OK) {
        goto cleanup;
    }

    PV_CHECK(vault.generation == initial_generation + 4U);
    PV_CHECK(retention_count_secure_managed(
        backup_directory,
        vault.vault_id
    ) == 2U);
    for (index = 0U; index < 2U; ++index) {
        const uint64_t generation = initial_generation + 2U + (uint64_t)index;

        PV_CHECK(retention_auto_path(
            expected_path,
            sizeof expected_path,
            backup_directory,
            vault.vault_id,
            generation
        ));
        PV_CHECK(retention_snapshot_has_generation(
            expected_path,
            recovery_key,
            generation,
            (size_t)(generation - initial_generation)
        ));
    }
    for (index = 0U; index < 2U; ++index) {
        const uint64_t generation = initial_generation + (uint64_t)index;

        PV_CHECK(retention_auto_path(
            expected_path,
            sizeof expected_path,
            backup_directory,
            vault.vault_id,
            generation
        ));
        PV_CHECK(access(expected_path, F_OK) != 0 && errno == ENOENT);
    }

    PV_CHECK(retention_make_path(
        symlink_target_path,
        sizeof symlink_target_path,
        directory,
        "symlink-target.bin"
    ));
    PV_CHECK(retention_write_fixture(
        symlink_target_path,
        symlink_target_bytes,
        sizeof symlink_target_bytes
    ));
    PV_CHECK(retention_auto_path(
        symlink_path,
        sizeof symlink_path,
        backup_directory,
        vault.vault_id,
        initial_generation + 22U
    ));
    PV_CHECK(symlink("../symlink-target.bin", symlink_path) == 0);

    PV_CHECK(retention_make_path(
        unsafe_source_path,
        sizeof unsafe_source_path,
        directory,
        "unsafe-source.bin"
    ));
    PV_CHECK(retention_write_fixture(
        unsafe_source_path,
        unsafe_candidate_bytes,
        sizeof unsafe_candidate_bytes
    ));
    PV_CHECK(retention_auto_path(
        unsafe_path,
        sizeof unsafe_path,
        backup_directory,
        vault.vault_id,
        initial_generation + 23U
    ));
    PV_CHECK(link(unsafe_source_path, unsafe_path) == 0);

    status = retention_add_record(&vault, 5U);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        status = pv_store_save(&vault, &header, 2U);
        PV_CHECK_STATUS(status, PV_OK);
    }
    if (status != PV_OK) {
        goto cleanup;
    }
    PV_CHECK(vault.generation == initial_generation + 5U);
    PV_CHECK(retention_count_secure_managed(
        backup_directory,
        vault.vault_id
    ) == 3U);

    for (index = 0U; index < fixture_count; ++index) {
        PV_CHECK(retention_file_equals(
            fixtures[index].path,
            fixtures[index].bytes,
            fixtures[index].length
        ));
    }
    {
        struct stat symlink_info;
        struct stat unsafe_info;
        struct stat unsafe_source_info;

        PV_CHECK(lstat(symlink_path, &symlink_info) == 0 &&
            S_ISLNK(symlink_info.st_mode));
        PV_CHECK(retention_readlink_equals(symlink_path, "../symlink-target.bin"));
        PV_CHECK(retention_file_equals(
            symlink_target_path,
            symlink_target_bytes,
            sizeof symlink_target_bytes
        ));
        PV_CHECK(lstat(unsafe_path, &unsafe_info) == 0 &&
            S_ISREG(unsafe_info.st_mode) && unsafe_info.st_nlink == 2);
        PV_CHECK(lstat(unsafe_source_path, &unsafe_source_info) == 0 &&
            unsafe_source_info.st_ino == unsafe_info.st_ino &&
            unsafe_source_info.st_dev == unsafe_info.st_dev);
        PV_CHECK(retention_file_equals(
            unsafe_path,
            unsafe_candidate_bytes,
            sizeof unsafe_candidate_bytes
        ));
        PV_CHECK(retention_file_equals(
            unsafe_source_path,
            unsafe_candidate_bytes,
            sizeof unsafe_candidate_bytes
        ));
    }

cleanup:
#ifdef PVAULT_TEST_FAULT_INJECTION
    pv_store_test_fault_reset();
#endif
    if (vault.arena.base != NULL) {
        pv_model_destroy(&vault);
    }
    sodium_memzero(&header, sizeof header);
    sodium_memzero(recovery_key, sizeof recovery_key);
    sodium_memzero(other_vault_id, sizeof other_vault_id);
    if (directory[0] != '\0') {
        pv_test_remove_temp_tree(directory);
    }
}

#ifdef PVAULT_TEST_FAULT_INJECTION
static void retention_retry_after_atomic_rename_is_idempotent(void)
{
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    uint8_t before_hash[crypto_generichash_BYTES];
    uint8_t after_hash[crypto_generichash_BYTES];
    char directory[PATH_MAX] = {0};
    char vault_path[PATH_MAX];
    char backup_directory[PATH_MAX];
    char automatic_path[PATH_MAX];
    pv_vault vault = {0};
    pv_file_header header = {0};
    uint64_t source_generation = 0U;
    pv_status status;

    retention_fill_recovery_key(recovery_key, 0x70U);
    sodium_memzero(before_hash, sizeof before_hash);
    sodium_memzero(after_hash, sizeof after_hash);
    pv_store_test_fault_reset();
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        goto cleanup;
    }
    PV_CHECK(retention_make_path(vault_path, sizeof vault_path, directory, "vault.pvlt"));
    PV_CHECK(retention_make_path(
        backup_directory,
        sizeof backup_directory,
        directory,
        "backups"
    ));
    if (!retention_create_and_open(vault_path, recovery_key, &vault, &header)) {
        goto cleanup;
    }
    source_generation = vault.generation;
    PV_CHECK(retention_auto_path(
        automatic_path,
        sizeof automatic_path,
        backup_directory,
        vault.vault_id,
        source_generation
    ));
    status = retention_add_record(&vault, 1U);
    PV_CHECK_STATUS(status, PV_OK);
    if (status != PV_OK) {
        goto cleanup;
    }

    pv_store_test_fault_reset();
    pv_store_test_fault_point_fail(PV_STORE_FAULT_POINT_ATOMIC_RENAME, EIO);
    status = pv_store_save(&vault, &header, 2U);
    PV_CHECK_STATUS(status, PV_ERR_IO);
    PV_CHECK(pv_store_test_fault_point_hit_count(
        PV_STORE_FAULT_POINT_ATOMIC_RENAME
    ) == 1U);
    PV_CHECK(pv_store_test_fault_point_hit_count(
        PV_STORE_FAULT_POINT_PRUNE_UNLINK
    ) == 0U);
    pv_store_test_fault_reset();
    PV_CHECK(vault.generation == source_generation);
    PV_CHECK(vault.dirty);
    PV_CHECK(retention_snapshot_has_generation(
        automatic_path,
        recovery_key,
        source_generation,
        0U
    ));
    PV_CHECK(retention_hash_file(automatic_path, before_hash));

    pv_store_test_fault_point_fail(
        PV_STORE_FAULT_POINT_AUTOMATIC_BACKUP_COLLISION_FSYNC,
        EIO
    );
    status = pv_store_save(&vault, &header, 2U);
    PV_CHECK_STATUS(status, PV_ERR_IO);
    PV_CHECK(pv_store_test_fault_point_hit_count(
        PV_STORE_FAULT_POINT_AUTOMATIC_BACKUP_COLLISION_FSYNC
    ) == 1U);
    pv_store_test_fault_reset();
    PV_CHECK(vault.generation == source_generation);
    PV_CHECK(vault.dirty);
    PV_CHECK(retention_snapshot_has_generation(
        vault_path,
        recovery_key,
        source_generation,
        0U
    ));
    PV_CHECK(retention_hash_file(automatic_path, after_hash));
    PV_CHECK(sodium_memcmp(
        before_hash,
        after_hash,
        sizeof before_hash
    ) == 0);

    status = pv_store_save(&vault, &header, 2U);
    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(vault.generation == source_generation + 1U);
    PV_CHECK(!vault.dirty);
    PV_CHECK(retention_hash_file(automatic_path, after_hash));
    PV_CHECK(sodium_memcmp(
        before_hash,
        after_hash,
        sizeof before_hash
    ) == 0);
    PV_CHECK(retention_count_secure_managed(
        backup_directory,
        vault.vault_id
    ) == 1U);
    PV_CHECK(retention_snapshot_has_generation(
        vault_path,
        recovery_key,
        source_generation + 1U,
        1U
    ));

cleanup:
    pv_store_test_fault_reset();
    if (vault.arena.base != NULL) {
        pv_model_destroy(&vault);
    }
    sodium_memzero(&header, sizeof header);
    sodium_memzero(recovery_key, sizeof recovery_key);
    sodium_memzero(before_hash, sizeof before_hash);
    sodium_memzero(after_hash, sizeof after_hash);
    if (directory[0] != '\0') {
        pv_test_remove_temp_tree(directory);
    }
}

static void retention_prune_failures_never_invalidate_committed_updates(void)
{
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    char directory[PATH_MAX] = {0};
    char vault_path[PATH_MAX];
    char backup_directory[PATH_MAX];
    pv_vault vault = {0};
    pv_file_header header = {0};
    pv_status status;

    retention_fill_recovery_key(recovery_key, 0x90U);
    pv_store_test_fault_reset();
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        goto cleanup;
    }
    PV_CHECK(retention_make_path(vault_path, sizeof vault_path, directory, "vault.pvlt"));
    PV_CHECK(retention_make_path(
        backup_directory,
        sizeof backup_directory,
        directory,
        "backups"
    ));
    if (!retention_create_and_open(vault_path, recovery_key, &vault, &header)) {
        goto cleanup;
    }

    status = retention_add_record(&vault, 1U);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        status = pv_store_save(&vault, &header, 1U);
        PV_CHECK_STATUS(status, PV_OK);
    }
    if (status != PV_OK) {
        goto cleanup;
    }

    status = retention_add_record(&vault, 2U);
    PV_CHECK_STATUS(status, PV_OK);
    pv_store_test_fault_reset();
    pv_store_test_fault_point_fail(PV_STORE_FAULT_POINT_PRUNE_UNLINK, EIO);
    if (status == PV_OK) {
        status = pv_store_save(&vault, &header, 1U);
        PV_CHECK_STATUS(status, PV_OK);
    }
    PV_CHECK(pv_store_test_fault_point_hit_count(
        PV_STORE_FAULT_POINT_PRUNE_UNLINK
    ) == 1U);
    pv_store_test_fault_reset();
    PV_CHECK(vault.generation == 3U);
    PV_CHECK(retention_snapshot_has_generation(vault_path, recovery_key, 3U, 2U));
    PV_CHECK(retention_count_secure_managed(backup_directory, vault.vault_id) == 2U);

    status = retention_add_record(&vault, 3U);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        status = pv_store_save(&vault, &header, 1U);
        PV_CHECK_STATUS(status, PV_OK);
    }
    PV_CHECK(retention_count_secure_managed(backup_directory, vault.vault_id) == 1U);

    status = retention_add_record(&vault, 4U);
    PV_CHECK_STATUS(status, PV_OK);
    pv_store_test_fault_reset();
    pv_store_test_fault_point_fail(PV_STORE_FAULT_POINT_PRUNE_DIR_FSYNC, EIO);
    if (status == PV_OK) {
        status = pv_store_save(&vault, &header, 1U);
        PV_CHECK_STATUS(status, PV_OK);
    }
    PV_CHECK(pv_store_test_fault_point_hit_count(
        PV_STORE_FAULT_POINT_PRUNE_DIR_FSYNC
    ) == 1U);
    pv_store_test_fault_reset();
    PV_CHECK(vault.generation == 5U);
    PV_CHECK(retention_snapshot_has_generation(vault_path, recovery_key, 5U, 4U));

    status = retention_add_record(&vault, 5U);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        status = pv_store_save(&vault, &header, 1U);
        PV_CHECK_STATUS(status, PV_OK);
    }
    PV_CHECK(vault.generation == 6U);
    PV_CHECK(retention_snapshot_has_generation(vault_path, recovery_key, 6U, 5U));
    PV_CHECK(retention_count_secure_managed(backup_directory, vault.vault_id) == 1U);

cleanup:
    pv_store_test_fault_reset();
    if (vault.arena.base != NULL) {
        pv_model_destroy(&vault);
    }
    sodium_memzero(&header, sizeof header);
    sodium_memzero(recovery_key, sizeof recovery_key);
    if (directory[0] != '\0') {
        pv_test_remove_temp_tree(directory);
    }
}
#endif

static void retention_different_collision_fails_without_overwrite(void)
{
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    char directory[PATH_MAX] = {0};
    char vault_path[PATH_MAX];
    char backup_directory[PATH_MAX];
    char collision_path[PATH_MAX];
    pv_vault vault = {0};
    pv_file_header header = {0};
    uint64_t source_generation = 0U;
    pv_status status;

#ifdef PVAULT_TEST_FAULT_INJECTION
    pv_store_test_fault_reset();
#endif
    retention_fill_recovery_key(recovery_key, 0xa0U);
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        goto cleanup;
    }
    PV_CHECK(retention_make_path(vault_path, sizeof vault_path, directory, "vault.pvlt"));
    PV_CHECK(retention_make_path(
        backup_directory,
        sizeof backup_directory,
        directory,
        "backups"
    ));
    if (!retention_create_and_open(vault_path, recovery_key, &vault, &header)) {
        goto cleanup;
    }
    source_generation = vault.generation;
    PV_CHECK(mkdir(backup_directory, 0700) == 0);
    PV_CHECK(retention_auto_path(
        collision_path,
        sizeof collision_path,
        backup_directory,
        vault.vault_id,
        source_generation
    ));
    PV_CHECK(retention_write_fixture(
        collision_path,
        collision_bytes,
        sizeof collision_bytes
    ));
    status = retention_add_record(&vault, 1U);
    PV_CHECK_STATUS(status, PV_OK);
    if (status != PV_OK) {
        goto cleanup;
    }

    status = pv_store_save(&vault, &header, 2U);
    PV_CHECK_STATUS(status, PV_ERR_EXISTS);
    PV_CHECK(vault.generation == source_generation);
    PV_CHECK(vault.dirty);
    PV_CHECK(retention_file_equals(
        collision_path,
        collision_bytes,
        sizeof collision_bytes
    ));
    PV_CHECK(retention_snapshot_has_generation(
        vault_path,
        recovery_key,
        source_generation,
        0U
    ));

cleanup:
#ifdef PVAULT_TEST_FAULT_INJECTION
    pv_store_test_fault_reset();
#endif
    if (vault.arena.base != NULL) {
        pv_model_destroy(&vault);
    }
    sodium_memzero(&header, sizeof header);
    sodium_memzero(recovery_key, sizeof recovery_key);
    if (directory[0] != '\0') {
        pv_test_remove_temp_tree(directory);
    }
}

static void retention_invalid_aead_candidate_aborts_entire_prune(void)
{
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    uint8_t invalid_hash_before[crypto_generichash_BYTES];
    uint8_t invalid_hash_after[crypto_generichash_BYTES];
    char directory[PATH_MAX] = {0};
    char vault_path[PATH_MAX];
    char backup_directory[PATH_MAX];
    char invalid_path[PATH_MAX];
    char authentic_path[PATH_MAX];
    pv_vault vault = {0};
    pv_file_header header = {0};
    uint64_t initial_generation = 0U;
    unsigned ordinal;
    pv_status status = PV_OK;

#ifdef PVAULT_TEST_FAULT_INJECTION
    pv_store_test_fault_reset();
#endif
    retention_fill_recovery_key(recovery_key, 0xb0U);
    sodium_memzero(invalid_hash_before, sizeof invalid_hash_before);
    sodium_memzero(invalid_hash_after, sizeof invalid_hash_after);
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        goto cleanup;
    }
    PV_CHECK(retention_make_path(vault_path, sizeof vault_path, directory, "vault.pvlt"));
    PV_CHECK(retention_make_path(
        backup_directory,
        sizeof backup_directory,
        directory,
        "backups"
    ));
    if (!retention_create_and_open(vault_path, recovery_key, &vault, &header)) {
        goto cleanup;
    }
    initial_generation = vault.generation;
    PV_CHECK(initial_generation == 1U);

    for (ordinal = 1U; ordinal <= 3U; ++ordinal) {
        status = retention_add_record(&vault, ordinal);
        PV_CHECK_STATUS(status, PV_OK);
        if (status == PV_OK) {
            status = pv_store_save(&vault, &header, 10U);
            PV_CHECK_STATUS(status, PV_OK);
        }
        if (status != PV_OK) {
            goto cleanup;
        }
    }
    PV_CHECK(retention_auto_path(
        invalid_path,
        sizeof invalid_path,
        backup_directory,
        vault.vault_id,
        initial_generation
    ));
    PV_CHECK(retention_header_has_vault_id(invalid_path, vault.vault_id));
    PV_CHECK(retention_flip_last_byte(invalid_path));
    PV_CHECK(retention_header_has_vault_id(invalid_path, vault.vault_id));
    PV_CHECK(!retention_snapshot_has_generation(
        invalid_path,
        recovery_key,
        initial_generation,
        0U
    ));
    PV_CHECK(retention_hash_file(invalid_path, invalid_hash_before));

    status = retention_add_record(&vault, 4U);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        status = pv_store_save(&vault, &header, 2U);
        PV_CHECK_STATUS(status, PV_OK);
    }
    if (status != PV_OK) {
        goto cleanup;
    }

    PV_CHECK(vault.generation == initial_generation + 4U);
    PV_CHECK(retention_snapshot_has_generation(
        vault_path,
        recovery_key,
        initial_generation + 4U,
        4U
    ));
    PV_CHECK(retention_count_secure_managed(
        backup_directory,
        vault.vault_id
    ) == 4U);
    PV_CHECK(retention_hash_file(invalid_path, invalid_hash_after));
    PV_CHECK(sodium_memcmp(
        invalid_hash_before,
        invalid_hash_after,
        sizeof invalid_hash_before
    ) == 0);
    for (ordinal = 1U; ordinal <= 3U; ++ordinal) {
        const uint64_t generation = initial_generation + (uint64_t)ordinal;

        PV_CHECK(retention_auto_path(
            authentic_path,
            sizeof authentic_path,
            backup_directory,
            vault.vault_id,
            generation
        ));
        PV_CHECK(retention_snapshot_has_generation(
            authentic_path,
            recovery_key,
            generation,
            (size_t)ordinal
        ));
    }

cleanup:
#ifdef PVAULT_TEST_FAULT_INJECTION
    pv_store_test_fault_reset();
#endif
    if (vault.arena.base != NULL) {
        pv_model_destroy(&vault);
    }
    sodium_memzero(&header, sizeof header);
    sodium_memzero(recovery_key, sizeof recovery_key);
    sodium_memzero(invalid_hash_before, sizeof invalid_hash_before);
    sodium_memzero(invalid_hash_after, sizeof invalid_hash_after);
    if (directory[0] != '\0') {
        pv_test_remove_temp_tree(directory);
    }
}

static void retention_authenticated_generation_mismatch_aborts_entire_prune(void)
{
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    uint8_t renamed_hash_before[crypto_generichash_BYTES];
    uint8_t renamed_hash_after[crypto_generichash_BYTES];
    char directory[PATH_MAX] = {0};
    char vault_path[PATH_MAX];
    char backup_directory[PATH_MAX];
    char generation_one_path[PATH_MAX];
    char false_generation_path[PATH_MAX];
    char authentic_path[PATH_MAX];
    pv_vault vault = {0};
    pv_file_header header = {0};
    uint64_t initial_generation = 0U;
    unsigned ordinal;
    pv_status status = PV_OK;

#ifdef PVAULT_TEST_FAULT_INJECTION
    pv_store_test_fault_reset();
#endif
    retention_fill_recovery_key(recovery_key, 0xd0U);
    sodium_memzero(renamed_hash_before, sizeof renamed_hash_before);
    sodium_memzero(renamed_hash_after, sizeof renamed_hash_after);
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        goto cleanup;
    }
    PV_CHECK(retention_make_path(vault_path, sizeof vault_path, directory, "vault.pvlt"));
    PV_CHECK(retention_make_path(
        backup_directory,
        sizeof backup_directory,
        directory,
        "backups"
    ));
    if (!retention_create_and_open(vault_path, recovery_key, &vault, &header)) {
        goto cleanup;
    }
    initial_generation = vault.generation;
    PV_CHECK(initial_generation == 1U);

    for (ordinal = 1U; ordinal <= 3U; ++ordinal) {
        status = retention_add_record(&vault, ordinal);
        PV_CHECK_STATUS(status, PV_OK);
        if (status == PV_OK) {
            status = pv_store_save(&vault, &header, 10U);
            PV_CHECK_STATUS(status, PV_OK);
        }
        if (status != PV_OK) {
            goto cleanup;
        }
    }
    PV_CHECK(retention_auto_path(
        generation_one_path,
        sizeof generation_one_path,
        backup_directory,
        vault.vault_id,
        initial_generation
    ));
    PV_CHECK(retention_auto_path(
        false_generation_path,
        sizeof false_generation_path,
        backup_directory,
        vault.vault_id,
        initial_generation + 1U
    ));
    PV_CHECK(unlink(false_generation_path) == 0);
    PV_CHECK(rename(generation_one_path, false_generation_path) == 0);
    PV_CHECK(retention_header_has_vault_id(false_generation_path, vault.vault_id));
    PV_CHECK(retention_snapshot_has_generation(
        false_generation_path,
        recovery_key,
        initial_generation,
        0U
    ));
    PV_CHECK(retention_hash_file(false_generation_path, renamed_hash_before));

    status = retention_add_record(&vault, 4U);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        status = pv_store_save(&vault, &header, 2U);
        PV_CHECK_STATUS(status, PV_OK);
    }
    if (status != PV_OK) {
        goto cleanup;
    }

    PV_CHECK(vault.generation == initial_generation + 4U);
    PV_CHECK(retention_snapshot_has_generation(
        vault_path,
        recovery_key,
        initial_generation + 4U,
        4U
    ));
    PV_CHECK(retention_count_secure_managed(
        backup_directory,
        vault.vault_id
    ) == 3U);
    PV_CHECK(retention_hash_file(false_generation_path, renamed_hash_after));
    PV_CHECK(sodium_memcmp(
        renamed_hash_before,
        renamed_hash_after,
        sizeof renamed_hash_before
    ) == 0);
    PV_CHECK(retention_snapshot_has_generation(
        false_generation_path,
        recovery_key,
        initial_generation,
        0U
    ));
    for (ordinal = 2U; ordinal <= 3U; ++ordinal) {
        const uint64_t generation = initial_generation + (uint64_t)ordinal;

        PV_CHECK(retention_auto_path(
            authentic_path,
            sizeof authentic_path,
            backup_directory,
            vault.vault_id,
            generation
        ));
        PV_CHECK(retention_snapshot_has_generation(
            authentic_path,
            recovery_key,
            generation,
            (size_t)ordinal
        ));
    }

cleanup:
#ifdef PVAULT_TEST_FAULT_INJECTION
    pv_store_test_fault_reset();
#endif
    if (vault.arena.base != NULL) {
        pv_model_destroy(&vault);
    }
    sodium_memzero(&header, sizeof header);
    sodium_memzero(recovery_key, sizeof recovery_key);
    sodium_memzero(renamed_hash_before, sizeof renamed_hash_before);
    sodium_memzero(renamed_hash_after, sizeof renamed_hash_after);
    if (directory[0] != '\0') {
        pv_test_remove_temp_tree(directory);
    }
}

static void retention_read_only_automatic_backup_is_pinned(void)
{
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    char directory[PATH_MAX] = {0};
    char vault_path[PATH_MAX];
    char backup_directory[PATH_MAX];
    char pinned_path[PATH_MAX];
    char expected_path[PATH_MAX];
    pv_vault vault = {0};
    pv_file_header header = {0};
    struct stat pinned_stat;
    uint64_t initial_generation = 0U;
    unsigned ordinal;
    pv_status status = PV_OK;

#ifdef PVAULT_TEST_FAULT_INJECTION
    pv_store_test_fault_reset();
#endif
    retention_fill_recovery_key(recovery_key, 0xe0U);
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        goto cleanup;
    }
    PV_CHECK(retention_make_path(vault_path, sizeof vault_path, directory, "vault.pvlt"));
    PV_CHECK(retention_make_path(
        backup_directory,
        sizeof backup_directory,
        directory,
        "backups"
    ));
    if (!retention_create_and_open(vault_path, recovery_key, &vault, &header)) {
        goto cleanup;
    }
    initial_generation = vault.generation;
    PV_CHECK(initial_generation == 1U);

    status = retention_add_record(&vault, 1U);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        status = pv_store_save(&vault, &header, 2U);
        PV_CHECK_STATUS(status, PV_OK);
    }
    if (status != PV_OK) {
        goto cleanup;
    }
    PV_CHECK(retention_auto_path(
        pinned_path,
        sizeof pinned_path,
        backup_directory,
        vault.vault_id,
        initial_generation
    ));
    PV_CHECK(chmod(pinned_path, 0400) == 0);
    PV_CHECK(retention_snapshot_has_generation(
        pinned_path,
        recovery_key,
        initial_generation,
        0U
    ));

    for (ordinal = 2U; ordinal <= 4U; ++ordinal) {
        status = retention_add_record(&vault, ordinal);
        PV_CHECK_STATUS(status, PV_OK);
        if (status == PV_OK) {
            status = pv_store_save(&vault, &header, 2U);
            PV_CHECK_STATUS(status, PV_OK);
        }
        if (status != PV_OK) {
            goto cleanup;
        }
    }

    PV_CHECK(vault.generation == initial_generation + 4U);
    PV_CHECK(retention_snapshot_has_generation(
        vault_path,
        recovery_key,
        initial_generation + 4U,
        4U
    ));
    PV_CHECK(lstat(pinned_path, &pinned_stat) == 0 &&
        S_ISREG(pinned_stat.st_mode) && pinned_stat.st_nlink == 1 &&
        (pinned_stat.st_mode & 07777U) == 0400U);
    PV_CHECK(retention_snapshot_has_generation(
        pinned_path,
        recovery_key,
        initial_generation,
        0U
    ));
    PV_CHECK(retention_count_secure_managed(
        backup_directory,
        vault.vault_id
    ) == 2U);

    PV_CHECK(retention_auto_path(
        expected_path,
        sizeof expected_path,
        backup_directory,
        vault.vault_id,
        initial_generation + 1U
    ));
    PV_CHECK(access(expected_path, F_OK) != 0 && errno == ENOENT);
    for (ordinal = 2U; ordinal <= 3U; ++ordinal) {
        const uint64_t generation = initial_generation + (uint64_t)ordinal;

        PV_CHECK(retention_auto_path(
            expected_path,
            sizeof expected_path,
            backup_directory,
            vault.vault_id,
            generation
        ));
        PV_CHECK(retention_snapshot_has_generation(
            expected_path,
            recovery_key,
            generation,
            (size_t)ordinal
        ));
    }

cleanup:
#ifdef PVAULT_TEST_FAULT_INJECTION
    pv_store_test_fault_reset();
#endif
    if (vault.arena.base != NULL) {
        pv_model_destroy(&vault);
    }
    sodium_memzero(&header, sizeof header);
    sodium_memzero(recovery_key, sizeof recovery_key);
    if (directory[0] != '\0') {
        pv_test_remove_temp_tree(directory);
    }
}

#ifdef PVAULT_TEST_FAULT_INJECTION
static void retention_snapshot_write_failure_is_cleanly_retryable(void)
{
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    char directory[PATH_MAX] = {0};
    char vault_path[PATH_MAX];
    char baseline_path[PATH_MAX];
    char backup_directory[PATH_MAX];
    char automatic_path[PATH_MAX];
    pv_vault vault = {0};
    pv_file_header header = {0};
    uint64_t initial_generation = 0U;
    pv_status status;

    retention_fill_recovery_key(recovery_key, 0x20U);
    pv_store_test_fault_reset();
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        goto cleanup;
    }
    PV_CHECK(retention_make_path(vault_path, sizeof vault_path, directory, "vault.pvlt"));
    PV_CHECK(retention_make_path(
        baseline_path,
        sizeof baseline_path,
        directory,
        "active-before-snapshot-write.pvlt"
    ));
    PV_CHECK(retention_make_path(
        backup_directory,
        sizeof backup_directory,
        directory,
        "backups"
    ));
    if (!retention_create_and_open(vault_path, recovery_key, &vault, &header)) {
        goto cleanup;
    }
    initial_generation = vault.generation;
    PV_CHECK(initial_generation == 1U);
    status = pv_store_backup(vault_path, baseline_path, vault.source_hash);
    PV_CHECK_STATUS(status, PV_OK);
    if (status != PV_OK) {
        goto cleanup;
    }
    PV_CHECK(retention_files_equal(vault_path, baseline_path));
    PV_CHECK(retention_auto_path(
        automatic_path,
        sizeof automatic_path,
        backup_directory,
        vault.vault_id,
        initial_generation
    ));
    status = retention_add_record(&vault, 1U);
    PV_CHECK_STATUS(status, PV_OK);
    if (status != PV_OK) {
        goto cleanup;
    }

    pv_store_test_fault_reset();
    pv_store_test_fault_point_fail(PV_STORE_FAULT_POINT_SNAPSHOT_WRITE, EIO);
    status = pv_store_save(&vault, &header, 2U);
    PV_CHECK_STATUS(status, PV_ERR_IO);
    PV_CHECK(pv_store_test_fault_point_hit_count(
        PV_STORE_FAULT_POINT_SNAPSHOT_WRITE
    ) == 1U);
    PV_CHECK(vault.generation == initial_generation);
    PV_CHECK(vault.dirty);
    PV_CHECK(retention_files_equal(vault_path, baseline_path));
    PV_CHECK(retention_snapshot_has_generation(
        vault_path,
        recovery_key,
        initial_generation,
        0U
    ));
    PV_CHECK(lstat(automatic_path, &(struct stat){0}) != 0 && errno == ENOENT);
    PV_CHECK(!retention_directory_has_temporary(directory));
    PV_CHECK(!retention_directory_has_temporary(backup_directory));

    pv_store_test_fault_reset();
    status = pv_store_save(&vault, &header, 2U);
    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(vault.generation == initial_generation + 1U);
    PV_CHECK(!vault.dirty);
    PV_CHECK(retention_snapshot_has_generation(
        vault_path,
        recovery_key,
        initial_generation + 1U,
        1U
    ));
    PV_CHECK(retention_snapshot_has_generation(
        automatic_path,
        recovery_key,
        initial_generation,
        0U
    ));
    PV_CHECK(retention_files_equal(automatic_path, baseline_path));
    PV_CHECK(!retention_directory_has_temporary(directory));
    PV_CHECK(!retention_directory_has_temporary(backup_directory));

cleanup:
    pv_store_test_fault_reset();
    if (vault.arena.base != NULL) {
        pv_model_destroy(&vault);
    }
    sodium_memzero(&header, sizeof header);
    sodium_memzero(recovery_key, sizeof recovery_key);
    if (directory[0] != '\0') {
        pv_test_remove_temp_tree(directory);
    }
}

static void retention_partial_prune_syncs_and_next_save_converges(void)
{
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    char directory[PATH_MAX] = {0};
    char vault_path[PATH_MAX];
    char backup_directory[PATH_MAX];
    char automatic_path[PATH_MAX];
    pv_vault vault = {0};
    pv_file_header header = {0};
    uint64_t initial_generation = 0U;
    unsigned ordinal;
    pv_status status = PV_OK;

    retention_fill_recovery_key(recovery_key, 0x30U);
    pv_store_test_fault_reset();
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        goto cleanup;
    }
    PV_CHECK(retention_make_path(vault_path, sizeof vault_path, directory, "vault.pvlt"));
    PV_CHECK(retention_make_path(
        backup_directory,
        sizeof backup_directory,
        directory,
        "backups"
    ));
    if (!retention_create_and_open(vault_path, recovery_key, &vault, &header)) {
        goto cleanup;
    }
    initial_generation = vault.generation;
    PV_CHECK(initial_generation == 1U);

    for (ordinal = 1U; ordinal <= 3U; ++ordinal) {
        status = retention_add_record(&vault, ordinal);
        PV_CHECK_STATUS(status, PV_OK);
        if (status == PV_OK) {
            status = pv_store_save(&vault, &header, 10U);
            PV_CHECK_STATUS(status, PV_OK);
        }
        if (status != PV_OK) {
            goto cleanup;
        }
    }
    PV_CHECK(retention_count_secure_managed(
        backup_directory,
        vault.vault_id
    ) == 3U);

    status = retention_add_record(&vault, 4U);
    PV_CHECK_STATUS(status, PV_OK);
    if (status != PV_OK) {
        goto cleanup;
    }
    pv_store_test_fault_reset();
    pv_store_test_fault_point_fail(
        PV_STORE_FAULT_POINT_PRUNE_AFTER_FIRST_UNLINK,
        EIO
    );
    status = pv_store_save(&vault, &header, 1U);
    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(pv_store_test_fault_point_hit_count(
        PV_STORE_FAULT_POINT_PRUNE_AFTER_FIRST_UNLINK
    ) == 1U);
    PV_CHECK(pv_store_test_fault_point_hit_count(
        PV_STORE_FAULT_POINT_PRUNE_DIR_FSYNC
    ) == 1U);
    PV_CHECK(vault.generation == initial_generation + 4U);
    PV_CHECK(!vault.dirty);
    PV_CHECK(retention_snapshot_has_generation(
        vault_path,
        recovery_key,
        initial_generation + 4U,
        4U
    ));
    PV_CHECK(retention_count_secure_managed(
        backup_directory,
        vault.vault_id
    ) == 3U);
    PV_CHECK(retention_auto_path(
        automatic_path,
        sizeof automatic_path,
        backup_directory,
        vault.vault_id,
        initial_generation
    ));
    PV_CHECK(access(automatic_path, F_OK) != 0 && errno == ENOENT);
    for (ordinal = 1U; ordinal <= 3U; ++ordinal) {
        const uint64_t generation = initial_generation + (uint64_t)ordinal;

        PV_CHECK(retention_auto_path(
            automatic_path,
            sizeof automatic_path,
            backup_directory,
            vault.vault_id,
            generation
        ));
        PV_CHECK(retention_snapshot_has_generation(
            automatic_path,
            recovery_key,
            generation,
            (size_t)ordinal
        ));
    }

    pv_store_test_fault_reset();
    status = retention_add_record(&vault, 5U);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        status = pv_store_save(&vault, &header, 1U);
        PV_CHECK_STATUS(status, PV_OK);
    }
    if (status != PV_OK) {
        goto cleanup;
    }
    PV_CHECK(vault.generation == initial_generation + 5U);
    PV_CHECK(!vault.dirty);
    PV_CHECK(retention_snapshot_has_generation(
        vault_path,
        recovery_key,
        initial_generation + 5U,
        5U
    ));
    PV_CHECK(retention_count_secure_managed(
        backup_directory,
        vault.vault_id
    ) == 1U);
    PV_CHECK(retention_auto_path(
        automatic_path,
        sizeof automatic_path,
        backup_directory,
        vault.vault_id,
        initial_generation + 4U
    ));
    PV_CHECK(retention_snapshot_has_generation(
        automatic_path,
        recovery_key,
        initial_generation + 4U,
        4U
    ));
    for (ordinal = 1U; ordinal <= 3U; ++ordinal) {
        PV_CHECK(retention_auto_path(
            automatic_path,
            sizeof automatic_path,
            backup_directory,
            vault.vault_id,
            initial_generation + (uint64_t)ordinal
        ));
        PV_CHECK(access(automatic_path, F_OK) != 0 && errno == ENOENT);
    }
    PV_CHECK(!retention_directory_has_temporary(directory));
    PV_CHECK(!retention_directory_has_temporary(backup_directory));

cleanup:
    pv_store_test_fault_reset();
    if (vault.arena.base != NULL) {
        pv_model_destroy(&vault);
    }
    sodium_memzero(&header, sizeof header);
    sodium_memzero(recovery_key, sizeof recovery_key);
    if (directory[0] != '\0') {
        pv_test_remove_temp_tree(directory);
    }
}
#endif

void pv_test_backup_retention_suite(void)
{
    pv_test_run(
        "backup_retention.keeps_owned_generations_and_private_snapshots",
        retention_keeps_owned_generations_and_private_snapshots
    );
    pv_test_run(
        "backup_retention.read_only_automatic_backup_is_pinned",
        retention_read_only_automatic_backup_is_pinned
    );
#ifdef PVAULT_TEST_FAULT_INJECTION
    pv_test_run(
        "backup_retention.retry_after_atomic_rename_is_idempotent",
        retention_retry_after_atomic_rename_is_idempotent
    );
    pv_test_run(
        "backup_retention.prune_failures_never_invalidate_committed_updates",
        retention_prune_failures_never_invalidate_committed_updates
    );
    pv_test_run(
        "backup_retention.snapshot_write_failure_is_cleanly_retryable",
        retention_snapshot_write_failure_is_cleanly_retryable
    );
    pv_test_run(
        "backup_retention.partial_prune_syncs_and_next_save_converges",
        retention_partial_prune_syncs_and_next_save_converges
    );
#endif
    pv_test_run(
        "backup_retention.different_collision_fails_without_overwrite",
        retention_different_collision_fails_without_overwrite
    );
    pv_test_run(
        "backup_retention.invalid_aead_candidate_aborts_entire_prune",
        retention_invalid_aead_candidate_aborts_entire_prune
    );
    pv_test_run(
        "backup_retention.authenticated_generation_mismatch_aborts_entire_prune",
        retention_authenticated_generation_mismatch_aborts_entire_prune
    );
}
