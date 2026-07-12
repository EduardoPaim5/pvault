#define _POSIX_C_SOURCE 200809L

#include "test.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct rescue_fixture {
    char root[PATH_MAX];
    char source[PATH_MAX];
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    uint8_t source_hash[crypto_generichash_BYTES];
    uint8_t *source_bytes;
    size_t source_len;
    size_t ciphertext_len;
    struct stat source_stat;
    pv_file_header source_header;
} rescue_fixture;

static const uint8_t rescue_password[] = "synthetic-rescue-master-password";
static const uint8_t rescue_title[] = "Synthetic rescue record";
static const uint8_t rescue_username[] = "rescue-user";
static const uint8_t rescue_secret[] = { 0x00U, 'r', 'e', 's', 'c', 'u', 'e', 0xffU };

static bool rescue_make_path(
    char *const output,
    const size_t output_len,
    const char *const directory,
    const char *const name
)
{
    const int written = snprintf(output, output_len, "%s/%s", directory, name);

    return written > 0 && (size_t)written < output_len;
}

static bool rescue_write_all(const int fd, const uint8_t *data, size_t length)
{
    while (length > 0U) {
        const ssize_t written = write(fd, data, length);

        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        data += (size_t)written;
        length -= (size_t)written;
    }
    return true;
}

static bool rescue_write_file(
    const char *const path,
    const uint8_t *const data,
    const size_t length,
    const mode_t mode
)
{
    int fd;
    bool success;

    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0) {
        return false;
    }
    success = rescue_write_all(fd, data, length);
    if (success && fsync(fd) != 0) {
        success = false;
    }
    if (close(fd) != 0) {
        success = false;
    }
    if (!success) {
        (void)unlink(path);
    }
    return success;
}

static bool rescue_read_file(
    const char *const path,
    uint8_t **const output,
    size_t *const output_len
)
{
    struct stat info;
    uint8_t *data;
    size_t used = 0U;
    size_t length;
    int fd;
    bool success = true;

    if (output == NULL || output_len == NULL) {
        return false;
    }
    *output = NULL;
    *output_len = 0U;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return false;
    }
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0 ||
        (uintmax_t)info.st_size > (uintmax_t)SIZE_MAX) {
        (void)close(fd);
        return false;
    }
    length = (size_t)info.st_size;
    data = malloc(length);
    if (data == NULL) {
        (void)close(fd);
        return false;
    }
    while (used < length) {
        const ssize_t got = read(fd, data + used, length - used);

        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            success = false;
            break;
        }
        used += (size_t)got;
    }
    if (close(fd) != 0) {
        success = false;
    }
    if (!success) {
        sodium_memzero(data, length);
        free(data);
        return false;
    }
    *output = data;
    *output_len = length;
    return true;
}

static void rescue_free_bytes(uint8_t **const data, size_t *const length)
{
    if (data != NULL && *data != NULL) {
        sodium_memzero(*data, length != NULL ? *length : 0U);
        free(*data);
        *data = NULL;
    }
    if (length != NULL) {
        *length = 0U;
    }
}

static bool rescue_add_synthetic_record(pv_vault *const vault)
{
    pv_record source;
    size_t index;

    sodium_memzero(&source, sizeof source);
    for (index = 0U; index < sizeof source.id; ++index) {
        source.id[index] = (uint8_t)(0x60U + (uint8_t)index);
    }
    source.title = (pv_slice){
        .data = (uint8_t *)(uintptr_t)rescue_title,
        .len = sizeof rescue_title - 1U
    };
    source.username = (pv_slice){
        .data = (uint8_t *)(uintptr_t)rescue_username,
        .len = sizeof rescue_username - 1U
    };
    source.password = (pv_slice){
        .data = (uint8_t *)(uintptr_t)rescue_secret,
        .len = sizeof rescue_secret
    };
    return pv_model_add_record(vault, &source, NULL) == PV_OK;
}

static bool rescue_fixture_init(rescue_fixture *const fixture)
{
    pv_vault vault = {0};
    pv_file_header header = {0};
    pv_status status;
    size_t index;
    bool initialized = false;

    if (fixture == NULL) {
        return false;
    }
    sodium_memzero(fixture, sizeof *fixture);
    if (!pv_test_make_temp_dir(fixture->root, sizeof fixture->root) ||
        !rescue_make_path(
            fixture->source,
            sizeof fixture->source,
            fixture->root,
            "source.pvlt"
        )) {
        return false;
    }
    for (index = 0U; index < sizeof fixture->recovery_key; ++index) {
        fixture->recovery_key[index] = (uint8_t)(0xa0U + (uint8_t)index);
    }
    status = pv_store_create(
        fixture->source,
        rescue_password,
        sizeof rescue_password - 1U,
        fixture->recovery_key,
        &vault
    );
    if (status != PV_OK) {
        goto cleanup;
    }
    status = pv_store_inspect(
        fixture->source,
        &header,
        &fixture->ciphertext_len
    );
    if (status != PV_OK || !rescue_add_synthetic_record(&vault)) {
        goto cleanup;
    }
    status = pv_store_save(&vault, &header, PV_DEFAULT_BACKUP_RETENTION);
    if (status != PV_OK) {
        goto cleanup;
    }
    (void)memcpy(fixture->source_hash, vault.source_hash, sizeof fixture->source_hash);
    status = pv_store_inspect(
        fixture->source,
        &fixture->source_header,
        &fixture->ciphertext_len
    );
    if (status != PV_OK || lstat(fixture->source, &fixture->source_stat) != 0 ||
        !rescue_read_file(
            fixture->source,
            &fixture->source_bytes,
            &fixture->source_len
        )) {
        goto cleanup;
    }
    initialized = true;

cleanup:
    pv_model_destroy(&vault);
    sodium_memzero(&header, sizeof header);
    if (!initialized) {
        rescue_free_bytes(&fixture->source_bytes, &fixture->source_len);
        pv_test_remove_temp_tree(fixture->root);
        sodium_memzero(fixture, sizeof *fixture);
    }
    return initialized;
}

static void rescue_fixture_destroy(rescue_fixture *const fixture)
{
    if (fixture == NULL) {
        return;
    }
    rescue_free_bytes(&fixture->source_bytes, &fixture->source_len);
    pv_test_remove_temp_tree(fixture->root);
    sodium_memzero(fixture, sizeof *fixture);
}

static bool rescue_source_is_unchanged(const rescue_fixture *const fixture)
{
    struct stat current;
    uint8_t *current_bytes = NULL;
    size_t current_len = 0U;
    bool matches;

    if (lstat(fixture->source, &current) != 0 ||
        !rescue_read_file(fixture->source, &current_bytes, &current_len)) {
        return false;
    }
    matches = current.st_dev == fixture->source_stat.st_dev &&
        current.st_ino == fixture->source_stat.st_ino &&
        current.st_mode == fixture->source_stat.st_mode &&
        current.st_nlink == fixture->source_stat.st_nlink &&
        current_len == fixture->source_len &&
        sodium_memcmp(current_bytes, fixture->source_bytes, current_len) == 0;
    rescue_free_bytes(&current_bytes, &current_len);
    return matches;
}

static bool rescue_snapshot_matches_fixture(
    const rescue_fixture *const fixture,
    const char *const path,
    const mode_t expected_mode
)
{
    struct stat info;
    uint8_t *bytes = NULL;
    size_t length = 0U;
    bool matches;

    if (lstat(path, &info) != 0 || !S_ISREG(info.st_mode) ||
        !rescue_read_file(path, &bytes, &length)) {
        return false;
    }
    matches = (info.st_mode & 07777) == expected_mode && info.st_uid == geteuid() &&
        info.st_nlink == 1 && length == fixture->source_len &&
        sodium_memcmp(bytes, fixture->source_bytes, length) == 0;
    rescue_free_bytes(&bytes, &length);
    return matches;
}

static bool rescue_open_has_synthetic_record(
    const rescue_fixture *const fixture,
    const char *const path,
    const bool recovery
)
{
    pv_vault vault = {0};
    pv_file_header header = {0};
    pv_status status;
    bool matches = false;

    status = recovery
        ? pv_store_open_recovery(path, fixture->recovery_key, &vault, &header)
        : pv_store_open_password(
            path,
            rescue_password,
            sizeof rescue_password - 1U,
            &vault,
            &header
        );
    if (status == PV_OK && vault.record_count == 1U &&
        sodium_memcmp(vault.source_hash, fixture->source_hash, sizeof vault.source_hash) == 0 &&
        sodium_memcmp(vault.vault_id, fixture->source_header.vault_id, PV_VAULT_ID_BYTES) == 0) {
        const pv_record *const record = &vault.records[0];

        matches = record->title.len == sizeof rescue_title - 1U &&
            sodium_memcmp(record->title.data, rescue_title, record->title.len) == 0 &&
            record->username.len == sizeof rescue_username - 1U &&
            sodium_memcmp(record->username.data, rescue_username, record->username.len) == 0 &&
            record->password.len == sizeof rescue_secret &&
            sodium_memcmp(record->password.data, rescue_secret, record->password.len) == 0;
    }
    pv_model_destroy(&vault);
    sodium_memzero(&header, sizeof header);
    return matches;
}

static bool rescue_has_temporary_entry(const char *const directory)
{
    DIR *stream;
    struct dirent *entry;
    bool found = false;

    stream = opendir(directory);
    if (stream == NULL) {
        return true;
    }
    while ((entry = readdir(stream)) != NULL) {
        if (strstr(entry->d_name, ".tmp.") != NULL) {
            found = true;
            break;
        }
    }
    (void)closedir(stream);
    return found;
}

static void rescue_inspect_is_non_mutating_and_recover_is_exact(void)
{
    rescue_fixture fixture;
    pv_file_header inspected = {0};
    size_t ciphertext_len = 0U;
    char output[PATH_MAX];
    struct stat output_stat;
    pv_status status;

    PV_CHECK(rescue_fixture_init(&fixture));
    if (fixture.root[0] == '\0') {
        return;
    }
    PV_CHECK(rescue_make_path(output, sizeof output, fixture.root, "recovered.pvlt"));

    status = pv_store_inspect(
        fixture.source,
        &inspected,
        &ciphertext_len
    );
    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(ciphertext_len == fixture.ciphertext_len);
    PV_CHECK(fixture.source_len == PV_FILE_HEADER_LEN + ciphertext_len);
    PV_CHECK(sodium_memcmp(
        inspected.vault_id,
        fixture.source_header.vault_id,
        PV_VAULT_ID_BYTES
    ) == 0);
    PV_CHECK(inspected.major == PV_FILE_MAJOR);
    PV_CHECK(inspected.minor == PV_FILE_MINOR);
    PV_CHECK(rescue_source_is_unchanged(&fixture));

    status = pv_store_recover_authenticated(
        fixture.source,
        output,
        fixture.source_hash
    );
    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(rescue_snapshot_matches_fixture(&fixture, output, 0400));
    PV_CHECK(lstat(output, &output_stat) == 0);
    if (lstat(output, &output_stat) == 0) {
        PV_CHECK(output_stat.st_ino != fixture.source_stat.st_ino ||
            output_stat.st_dev != fixture.source_stat.st_dev);
    }
    PV_CHECK(rescue_open_has_synthetic_record(&fixture, output, false));
    PV_CHECK(rescue_open_has_synthetic_record(&fixture, output, true));
    PV_CHECK(rescue_source_is_unchanged(&fixture));
    PV_CHECK(!rescue_has_temporary_entry(fixture.root));

    sodium_memzero(&inspected, sizeof inspected);
    rescue_fixture_destroy(&fixture);
}

static void rescue_rejects_wrong_hash_and_existing_destinations(void)
{
    static const uint8_t marker[] = "existing destination must survive";
    rescue_fixture fixture;
    uint8_t wrong_hash[crypto_generichash_BYTES];
    char output[PATH_MAX];
    char regular[PATH_MAX];
    char symlink_path[PATH_MAX];
    char directory_path[PATH_MAX];
    struct stat regular_before;
    struct stat regular_after;
    uint8_t *regular_bytes = NULL;
    size_t regular_len = 0U;
    char link_target[64] = {0};
    ssize_t link_len;
    pv_status status;

    PV_CHECK(rescue_fixture_init(&fixture));
    if (fixture.root[0] == '\0') {
        return;
    }
    PV_CHECK(rescue_make_path(output, sizeof output, fixture.root, "wrong-hash.pvlt"));
    (void)memcpy(wrong_hash, fixture.source_hash, sizeof wrong_hash);
    wrong_hash[0] ^= 0x80U;
    status = pv_store_recover_authenticated(fixture.source, output, wrong_hash);
    PV_CHECK_STATUS(status, PV_ERR_AUTH);
    PV_CHECK(lstat(output, &regular_after) != 0 && errno == ENOENT);
    PV_CHECK(rescue_source_is_unchanged(&fixture));

    PV_CHECK(rescue_make_path(regular, sizeof regular, fixture.root, "existing.pvlt"));
    PV_CHECK(rescue_write_file(regular, marker, sizeof marker, 0600));
    PV_CHECK(lstat(regular, &regular_before) == 0);
    status = pv_store_recover_authenticated(
        fixture.source,
        regular,
        fixture.source_hash
    );
    PV_CHECK_STATUS(status, PV_ERR_EXISTS);
    PV_CHECK(lstat(regular, &regular_after) == 0);
    PV_CHECK(regular_after.st_dev == regular_before.st_dev);
    PV_CHECK(regular_after.st_ino == regular_before.st_ino);
    PV_CHECK(regular_after.st_mode == regular_before.st_mode);
    PV_CHECK(rescue_read_file(regular, &regular_bytes, &regular_len));
    PV_CHECK(regular_len == sizeof marker);
    if (regular_len == sizeof marker) {
        PV_CHECK(sodium_memcmp(regular_bytes, marker, sizeof marker) == 0);
    }
    rescue_free_bytes(&regular_bytes, &regular_len);

    PV_CHECK(rescue_make_path(symlink_path, sizeof symlink_path, fixture.root, "existing-link.pvlt"));
    PV_CHECK(symlink("do-not-follow", symlink_path) == 0);
    status = pv_store_recover_authenticated(
        fixture.source,
        symlink_path,
        fixture.source_hash
    );
    PV_CHECK_STATUS(status, PV_ERR_EXISTS);
    PV_CHECK(lstat(symlink_path, &regular_after) == 0 && S_ISLNK(regular_after.st_mode));
    link_len = readlink(symlink_path, link_target, sizeof link_target - 1U);
    PV_CHECK(link_len == (ssize_t)(sizeof "do-not-follow" - 1U));
    if (link_len > 0 && (size_t)link_len < sizeof link_target) {
        link_target[link_len] = '\0';
        PV_CHECK(strcmp(link_target, "do-not-follow") == 0);
    }

    PV_CHECK(rescue_make_path(directory_path, sizeof directory_path, fixture.root, "existing-directory.pvlt"));
    PV_CHECK(mkdir(directory_path, 0700) == 0);
    status = pv_store_recover_authenticated(
        fixture.source,
        directory_path,
        fixture.source_hash
    );
    PV_CHECK_STATUS(status, PV_ERR_EXISTS);
    PV_CHECK(lstat(directory_path, &regular_after) == 0 && S_ISDIR(regular_after.st_mode));
    PV_CHECK(rescue_source_is_unchanged(&fixture));
    PV_CHECK(!rescue_has_temporary_entry(fixture.root));

    sodium_memzero(wrong_hash, sizeof wrong_hash);
    rescue_fixture_destroy(&fixture);
}

static void rescue_rejects_tampering_and_invalid_format(void)
{
    rescue_fixture fixture;
    uint8_t *tampered = NULL;
    size_t tampered_len = 0U;
    char tampered_path[PATH_MAX];
    char invalid_path[PATH_MAX];
    char output[PATH_MAX];
    pv_file_header inspected = {0};
    size_t ciphertext_len = 0U;
    struct stat info;
    pv_status status;

    PV_CHECK(rescue_fixture_init(&fixture));
    if (fixture.root[0] == '\0') {
        return;
    }
    PV_CHECK(rescue_make_path(tampered_path, sizeof tampered_path, fixture.root, "tampered.pvlt"));
    PV_CHECK(rescue_make_path(invalid_path, sizeof invalid_path, fixture.root, "invalid.pvlt"));
    PV_CHECK(rescue_make_path(output, sizeof output, fixture.root, "rejected-output.pvlt"));
    tampered = malloc(fixture.source_len);
    PV_CHECK(tampered != NULL);
    if (tampered == NULL) {
        rescue_fixture_destroy(&fixture);
        return;
    }
    (void)memcpy(tampered, fixture.source_bytes, fixture.source_len);
    tampered_len = fixture.source_len;
    tampered[tampered_len - 1U] ^= 0x01U;
    PV_CHECK(rescue_write_file(tampered_path, tampered, tampered_len, 0600));
    status = pv_store_inspect(
        tampered_path,
        &inspected,
        &ciphertext_len
    );
    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(ciphertext_len == fixture.ciphertext_len);
    status = pv_store_recover_authenticated(
        tampered_path,
        output,
        fixture.source_hash
    );
    PV_CHECK_STATUS(status, PV_ERR_AUTH);
    PV_CHECK(lstat(output, &info) != 0 && errno == ENOENT);

    (void)memcpy(tampered, fixture.source_bytes, fixture.source_len);
    tampered[0] ^= 0xffU;
    PV_CHECK(rescue_write_file(invalid_path, tampered, tampered_len, 0600));
    sodium_memzero(&inspected, sizeof inspected);
    status = pv_store_inspect(
        invalid_path,
        &inspected,
        &ciphertext_len
    );
    PV_CHECK_STATUS(status, PV_ERR_FORMAT);
    {
        const pv_file_header cleared = {0};

        PV_CHECK(sodium_memcmp(&inspected, &cleared, sizeof cleared) == 0);
        PV_CHECK(ciphertext_len == 0U);
    }
    status = pv_store_recover_authenticated(
        invalid_path,
        output,
        fixture.source_hash
    );
    PV_CHECK_STATUS(status, PV_ERR_FORMAT);
    PV_CHECK(lstat(output, &info) != 0 && errno == ENOENT);
    PV_CHECK(rescue_source_is_unchanged(&fixture));
    PV_CHECK(!rescue_has_temporary_entry(fixture.root));

    rescue_free_bytes(&tampered, &tampered_len);
    sodium_memzero(&inspected, sizeof inspected);
    rescue_fixture_destroy(&fixture);
}

#ifdef PVAULT_TEST_FAULT_INJECTION
static void rescue_prepublish_faults_leave_no_output(void)
{
    static const pv_store_fault_point points[] = {
        PV_STORE_FAULT_POINT_SNAPSHOT_OPEN,
        PV_STORE_FAULT_POINT_SNAPSHOT_WRITE,
        PV_STORE_FAULT_POINT_SNAPSHOT_FSYNC
    };
    rescue_fixture fixture;
    size_t index;

    PV_CHECK(rescue_fixture_init(&fixture));
    if (fixture.root[0] == '\0') {
        return;
    }
    for (index = 0U; index < sizeof points / sizeof points[0]; ++index) {
        char output[PATH_MAX];
        struct stat info;
        pv_status status;

        PV_CHECK(rescue_make_path(output, sizeof output, fixture.root, "prepublish-failure.pvlt"));
        pv_store_test_fault_reset();
        pv_store_test_fault_point_fail(points[index], EIO);
        status = pv_store_recover_authenticated(
            fixture.source,
            output,
            fixture.source_hash
        );
        PV_CHECK_STATUS(status, PV_ERR_IO);
        PV_CHECK(pv_store_test_fault_point_hit_count(points[index]) == 1U);
        pv_store_test_fault_reset();
        PV_CHECK(lstat(output, &info) != 0 && errno == ENOENT);
        PV_CHECK(rescue_source_is_unchanged(&fixture));
        PV_CHECK(!rescue_has_temporary_entry(fixture.root));
    }
    pv_store_test_fault_reset();
    rescue_fixture_destroy(&fixture);
}

static void rescue_postpublish_failures_preserve_published_copy(void)
{
    static const pv_store_fault_point points[] = {
        PV_STORE_FAULT_POINT_SNAPSHOT_PARENT_FSYNC,
        PV_STORE_FAULT_POINT_SNAPSHOT_READBACK
    };
    static const char *const names[] = {
        "parent-fsync-uncertain.pvlt",
        "readback-uncertain.pvlt"
    };
    rescue_fixture fixture;
    size_t index;

    PV_CHECK(rescue_fixture_init(&fixture));
    if (fixture.root[0] == '\0') {
        return;
    }
    for (index = 0U; index < sizeof points / sizeof points[0]; ++index) {
        char output[PATH_MAX];
        pv_status status;

        PV_CHECK(rescue_make_path(output, sizeof output, fixture.root, names[index]));
        pv_store_test_fault_reset();
        pv_store_test_fault_point_fail(points[index], EIO);
        status = pv_store_recover_authenticated(
            fixture.source,
            output,
            fixture.source_hash
        );
        PV_CHECK_STATUS(status, PV_ERR_DURABILITY);
        PV_CHECK(pv_store_test_fault_point_hit_count(points[index]) == 1U);
        pv_store_test_fault_reset();
        PV_CHECK(rescue_snapshot_matches_fixture(&fixture, output, 0400));
        PV_CHECK(rescue_open_has_synthetic_record(&fixture, output, false));
        PV_CHECK(rescue_open_has_synthetic_record(&fixture, output, true));
        PV_CHECK(rescue_source_is_unchanged(&fixture));
        PV_CHECK(!rescue_has_temporary_entry(fixture.root));
    }

    pv_store_test_fault_reset();
    rescue_fixture_destroy(&fixture);
}
#endif

void pv_test_rescue_suite(void)
{
    pv_test_run(
        "rescue.inspect_is_non_mutating_and_recover_is_exact",
        rescue_inspect_is_non_mutating_and_recover_is_exact
    );
    pv_test_run(
        "rescue.rejects_wrong_hash_and_existing_destinations",
        rescue_rejects_wrong_hash_and_existing_destinations
    );
    pv_test_run(
        "rescue.rejects_tampering_and_invalid_format",
        rescue_rejects_tampering_and_invalid_format
    );
#ifdef PVAULT_TEST_FAULT_INJECTION
    pv_test_run(
        "rescue.prepublish_faults_leave_no_output",
        rescue_prepublish_faults_leave_no_output
    );
    pv_test_run(
        "rescue.postpublish_failures_preserve_published_copy",
        rescue_postpublish_failures_preserve_published_copy
    );
#endif
}
