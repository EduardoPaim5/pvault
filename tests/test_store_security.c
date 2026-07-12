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

typedef struct store_security_fixture {
    char root[PATH_MAX];
    char active[PATH_MAX];
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    uint8_t active_hash[crypto_generichash_BYTES];
} store_security_fixture;

static const uint8_t store_security_password[] = "synthetic-store-security-master";

void pv_test_store_security_suite(void);

static bool security_make_path(
    char *const output,
    const size_t output_len,
    const char *const directory,
    const char *const name
)
{
    const int written = snprintf(output, output_len, "%s/%s", directory, name);

    return written > 0 && (size_t)written < output_len;
}

static void security_fill_recovery_key(uint8_t key[PV_RECOVERY_KEY_BYTES])
{
    size_t index;

    for (index = 0U; index < PV_RECOVERY_KEY_BYTES; ++index) {
        key[index] = (uint8_t)(0x30U + (uint8_t)index);
    }
}

static bool security_write_all(const int fd, const uint8_t *data, size_t length)
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

static bool security_copy_file(const char *const source, const char *const destination)
{
    uint8_t buffer[16384];
    int input = -1;
    int output = -1;
    bool success = true;

    input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) {
        return false;
    }
    output = open(
        destination,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0600
    );
    if (output < 0) {
        (void)close(input);
        return false;
    }
    for (;;) {
        ssize_t got;

        do {
            got = read(input, buffer, sizeof buffer);
        } while (got < 0 && errno == EINTR);
        if (got < 0) {
            success = false;
            break;
        }
        if (got == 0) {
            break;
        }
        if (!security_write_all(output, buffer, (size_t)got)) {
            success = false;
            break;
        }
    }
    if (success && fsync(output) != 0) {
        success = false;
    }
    if (close(input) != 0) {
        success = false;
    }
    if (close(output) != 0) {
        success = false;
    }
    sodium_memzero(buffer, sizeof buffer);
    if (!success) {
        (void)unlink(destination);
    }
    return success;
}

static bool security_read_file(
    const char *const path,
    uint8_t **const output,
    size_t *const output_len
)
{
    struct stat info;
    uint8_t *data = NULL;
    size_t used = 0U;
    size_t length;
    int fd;
    bool success = true;

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

static bool security_replace_file(
    const char *const path,
    const uint8_t *const data,
    const size_t length
)
{
    int fd;
    bool success;

    fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return false;
    }
    success = security_write_all(fd, data, length);
    if (success && fsync(fd) != 0) {
        success = false;
    }
    if (fchmod(fd, 0600) != 0) {
        success = false;
    }
    if (close(fd) != 0) {
        success = false;
    }
    return success;
}

static bool security_path_absent(const char *const path)
{
    struct stat info;

    errno = 0;
    return lstat(path, &info) != 0 && errno == ENOENT;
}

static bool security_path_identity_matches(
    const char *const path,
    const struct stat *const expected
)
{
    struct stat current;

    return lstat(path, &current) == 0 &&
        current.st_dev == expected->st_dev &&
        current.st_ino == expected->st_ino;
}

static bool security_create_snapshot(
    const char *const path,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    uint8_t hash[crypto_generichash_BYTES]
)
{
    pv_vault vault = {0};
    const pv_status status = pv_store_create(
        path,
        store_security_password,
        sizeof store_security_password - 1U,
        recovery_key,
        &vault
    );

    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        memcpy(hash, vault.source_hash, crypto_generichash_BYTES);
    }
    pv_model_destroy(&vault);
    return status == PV_OK;
}

static bool security_fixture_init(store_security_fixture *const fixture)
{
    memset(fixture, 0, sizeof *fixture);
    if (!pv_test_make_temp_dir(fixture->root, sizeof fixture->root)) {
        PV_CHECK(false);
        return false;
    }
    if (!security_make_path(
            fixture->active,
            sizeof fixture->active,
            fixture->root,
            "active.pvlt"
        )) {
        PV_CHECK(false);
        return false;
    }
    security_fill_recovery_key(fixture->recovery_key);
    if (!security_create_snapshot(
            fixture->active,
            fixture->recovery_key,
            fixture->active_hash
        )) {
        return false;
    }
    PV_CHECK(chmod(fixture->root, 0700) == 0);
    PV_CHECK(chmod(fixture->active, 0600) == 0);
    return true;
}

static void security_fixture_destroy(store_security_fixture *const fixture)
{
    if (fixture->root[0] != '\0') {
        (void)chmod(fixture->root, 0700);
        pv_test_remove_temp_tree(fixture->root);
    }
    sodium_memzero(fixture, sizeof *fixture);
}

static void security_expect_open_status(
    const store_security_fixture *const fixture,
    const char *const path,
    const pv_status expected
)
{
    pv_vault vault = {0};
    pv_file_header header = {0};
    pv_status status;

    status = pv_store_open_password(
        path,
        store_security_password,
        sizeof store_security_password - 1U,
        &vault,
        &header
    );
    PV_CHECK_STATUS(status, expected);
    if (status == PV_OK) {
        PV_CHECK(
            sodium_memcmp(
                vault.source_hash,
                fixture->active_hash,
                crypto_generichash_BYTES
            ) == 0
        );
    }
    pv_model_destroy(&vault);
    sodium_memzero(&header, sizeof header);

    status = pv_store_open_recovery(path, fixture->recovery_key, &vault, &header);
    PV_CHECK_STATUS(status, expected);
    if (status == PV_OK) {
        PV_CHECK(
            sodium_memcmp(
                vault.source_hash,
                fixture->active_hash,
                crypto_generichash_BYTES
            ) == 0
        );
    }
    pv_model_destroy(&vault);
    sodium_memzero(&header, sizeof header);
}

static void store_security_open_rejects_unsafe_snapshot_metadata(void)
{
    static const mode_t unsafe_modes[] = {0000, 0644, 0660, 0700, 02600, 04600};
    store_security_fixture fixture;
    char hardlink_path[PATH_MAX];
    char symlink_path[PATH_MAX];
    char directory_path[PATH_MAX];
    size_t index;

    if (!security_fixture_init(&fixture)) {
        security_fixture_destroy(&fixture);
        return;
    }
    PV_CHECK(security_make_path(hardlink_path, sizeof hardlink_path, fixture.root, "hard.pvlt"));
    PV_CHECK(security_make_path(symlink_path, sizeof symlink_path, fixture.root, "link.pvlt"));
    PV_CHECK(security_make_path(directory_path, sizeof directory_path, fixture.root, "directory.pvlt"));

    security_expect_open_status(&fixture, fixture.active, PV_OK);
    if (chmod(fixture.active, 0400) == 0) {
        security_expect_open_status(&fixture, fixture.active, PV_OK);
    } else {
        PV_CHECK(false);
    }
    PV_CHECK(chmod(fixture.active, 0600) == 0);
    if (chmod(fixture.root, 0755) == 0) {
        security_expect_open_status(&fixture, fixture.active, PV_OK);
    } else {
        PV_CHECK(false);
    }
    PV_CHECK(chmod(fixture.root, 0700) == 0);

    for (index = 0U; index < sizeof unsafe_modes / sizeof unsafe_modes[0]; ++index) {
        if (chmod(fixture.active, unsafe_modes[index]) == 0) {
            security_expect_open_status(&fixture, fixture.active, PV_ERR_IO);
        } else {
            PV_CHECK(false);
        }
    }
    PV_CHECK(chmod(fixture.active, 0600) == 0);

    if (link(fixture.active, hardlink_path) == 0) {
        security_expect_open_status(&fixture, hardlink_path, PV_ERR_IO);
        PV_CHECK(unlink(hardlink_path) == 0);
    } else {
        PV_CHECK(false);
    }
    if (symlink(fixture.active, symlink_path) == 0) {
        security_expect_open_status(&fixture, symlink_path, PV_ERR_IO);
        PV_CHECK(unlink(symlink_path) == 0);
    } else {
        PV_CHECK(false);
    }
    if (mkdir(directory_path, 0700) == 0) {
        security_expect_open_status(&fixture, directory_path, PV_ERR_IO);
        PV_CHECK(rmdir(directory_path) == 0);
    } else {
        PV_CHECK(false);
    }

    if (chmod(fixture.root, 0775) == 0) {
        security_expect_open_status(&fixture, fixture.active, PV_ERR_IO);
    } else {
        PV_CHECK(false);
    }
    if (chmod(fixture.root, 0777) == 0) {
        security_expect_open_status(&fixture, fixture.active, PV_ERR_IO);
    } else {
        PV_CHECK(false);
    }
    PV_CHECK(chmod(fixture.root, 0700) == 0);
    security_fixture_destroy(&fixture);
}

static void security_expect_backup_rejected(
    const char *const source,
    const char *const destination
)
{
    const pv_status status = pv_store_backup(source, destination, NULL);

    PV_CHECK_STATUS(status, PV_ERR_IO);
    PV_CHECK(security_path_absent(destination));
    (void)unlink(destination);
}

static void store_security_backup_rejects_unsafe_source_before_destination(void)
{
    static const mode_t unsafe_modes[] = {0000, 0644, 0660, 0700, 02600, 04600};
    store_security_fixture fixture;
    char output_directory[PATH_MAX];
    char destination[PATH_MAX];
    char hardlink_path[PATH_MAX];
    char symlink_path[PATH_MAX];
    char directory_path[PATH_MAX];
    char source_parent[PATH_MAX];
    char nested_source[PATH_MAX];
    struct stat info;
    pv_status status;
    size_t index;

    if (!security_fixture_init(&fixture)) {
        security_fixture_destroy(&fixture);
        return;
    }
    PV_CHECK(security_make_path(output_directory, sizeof output_directory, fixture.root, "outputs"));
    PV_CHECK(security_make_path(destination, sizeof destination, output_directory, "snapshot.bin"));
    PV_CHECK(security_make_path(hardlink_path, sizeof hardlink_path, fixture.root, "hard.pvlt"));
    PV_CHECK(security_make_path(symlink_path, sizeof symlink_path, fixture.root, "link.pvlt"));
    PV_CHECK(security_make_path(directory_path, sizeof directory_path, fixture.root, "directory.pvlt"));
    PV_CHECK(security_make_path(source_parent, sizeof source_parent, fixture.root, "source-parent"));
    PV_CHECK(security_make_path(nested_source, sizeof nested_source, source_parent, "nested.pvlt"));
    if (mkdir(output_directory, 0700) != 0 || mkdir(source_parent, 0700) != 0) {
        PV_CHECK(false);
        security_fixture_destroy(&fixture);
        return;
    }

    status = pv_store_backup(fixture.active, destination, NULL);
    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(lstat(destination, &info) == 0);
    if (lstat(destination, &info) == 0) {
        PV_CHECK(S_ISREG(info.st_mode));
        PV_CHECK((info.st_mode & 0777U) == 0600U);
    }
    (void)unlink(destination);

    PV_CHECK(chmod(fixture.active, 0400) == 0);
    status = pv_store_backup(fixture.active, destination, NULL);
    PV_CHECK_STATUS(status, PV_OK);
    (void)unlink(destination);
    PV_CHECK(chmod(fixture.active, 0600) == 0);

    for (index = 0U; index < sizeof unsafe_modes / sizeof unsafe_modes[0]; ++index) {
        if (chmod(fixture.active, unsafe_modes[index]) == 0) {
            security_expect_backup_rejected(fixture.active, destination);
        } else {
            PV_CHECK(false);
        }
    }
    PV_CHECK(chmod(fixture.active, 0600) == 0);

    if (link(fixture.active, hardlink_path) == 0) {
        security_expect_backup_rejected(hardlink_path, destination);
        PV_CHECK(unlink(hardlink_path) == 0);
    } else {
        PV_CHECK(false);
    }
    if (symlink(fixture.active, symlink_path) == 0) {
        security_expect_backup_rejected(symlink_path, destination);
        PV_CHECK(unlink(symlink_path) == 0);
    } else {
        PV_CHECK(false);
    }
    if (mkdir(directory_path, 0700) == 0) {
        security_expect_backup_rejected(directory_path, destination);
        PV_CHECK(rmdir(directory_path) == 0);
    } else {
        PV_CHECK(false);
    }

    if (security_copy_file(fixture.active, nested_source)) {
        if (chmod(source_parent, 0775) == 0) {
            security_expect_backup_rejected(nested_source, destination);
        } else {
            PV_CHECK(false);
        }
        if (chmod(source_parent, 0777) == 0) {
            security_expect_backup_rejected(nested_source, destination);
        } else {
            PV_CHECK(false);
        }
        PV_CHECK(chmod(source_parent, 0700) == 0);
    } else {
        PV_CHECK(false);
    }
    security_fixture_destroy(&fixture);
}

static bool security_files_equal(
    const char *const path,
    const uint8_t *const expected,
    const size_t expected_len
)
{
    uint8_t *actual = NULL;
    size_t actual_len = 0U;
    bool equal = false;

    if (security_read_file(path, &actual, &actual_len)) {
        equal = actual_len == expected_len &&
            sodium_memcmp(actual, expected, expected_len) == 0;
    }
    if (actual != NULL) {
        sodium_memzero(actual, actual_len);
        free(actual);
    }
    return equal;
}

static void security_expect_restore_rejected(
    const store_security_fixture *const fixture,
    const char *const candidate,
    const uint8_t candidate_hash[crypto_generichash_BYTES],
    const uint8_t *const active_bytes,
    const size_t active_len,
    const char *const pre_restore_directory
)
{
    const pv_status status = pv_store_restore(
        fixture->active,
        candidate,
        candidate_hash
    );
    const bool unchanged = security_files_equal(
        fixture->active,
        active_bytes,
        active_len
    );

    PV_CHECK_STATUS(status, PV_ERR_IO);
    PV_CHECK(unchanged);
    PV_CHECK(security_path_absent(pre_restore_directory));

    if (!unchanged) {
        PV_CHECK(security_replace_file(fixture->active, active_bytes, active_len));
    }
    if (!security_path_absent(pre_restore_directory)) {
        pv_test_remove_temp_tree(pre_restore_directory);
    }
}

static void store_security_restore_rejects_unsafe_candidate_without_side_effects(void)
{
    static const mode_t unsafe_modes[] = {0000, 0644, 0660, 0700, 02600, 04600};
    store_security_fixture fixture;
    char candidate_base[PATH_MAX];
    char hardlink_path[PATH_MAX];
    char symlink_path[PATH_MAX];
    char directory_path[PATH_MAX];
    char candidate_parent[PATH_MAX];
    char nested_candidate[PATH_MAX];
    char pre_restore_directory[PATH_MAX];
    uint8_t candidate_hash[crypto_generichash_BYTES] = {0};
    uint8_t *active_bytes = NULL;
    size_t active_len = 0U;
    size_t index;

    if (!security_fixture_init(&fixture)) {
        security_fixture_destroy(&fixture);
        return;
    }
    PV_CHECK(security_make_path(candidate_base, sizeof candidate_base, fixture.root, "candidate.pvlt"));
    PV_CHECK(security_make_path(hardlink_path, sizeof hardlink_path, fixture.root, "candidate-hard.pvlt"));
    PV_CHECK(security_make_path(symlink_path, sizeof symlink_path, fixture.root, "candidate-link.pvlt"));
    PV_CHECK(security_make_path(directory_path, sizeof directory_path, fixture.root, "candidate-directory.pvlt"));
    PV_CHECK(security_make_path(candidate_parent, sizeof candidate_parent, fixture.root, "candidate-parent"));
    PV_CHECK(security_make_path(nested_candidate, sizeof nested_candidate, candidate_parent, "nested.pvlt"));
    PV_CHECK(security_make_path(pre_restore_directory, sizeof pre_restore_directory, fixture.root, "backups"));
    if (!security_create_snapshot(candidate_base, fixture.recovery_key, candidate_hash) ||
        !security_read_file(fixture.active, &active_bytes, &active_len)) {
        PV_CHECK(false);
        security_fixture_destroy(&fixture);
        return;
    }
    PV_CHECK(
        active_len > 0U &&
        !security_files_equal(candidate_base, active_bytes, active_len)
    );

    for (index = 0U; index < sizeof unsafe_modes / sizeof unsafe_modes[0]; ++index) {
        if (chmod(candidate_base, unsafe_modes[index]) == 0) {
            security_expect_restore_rejected(
                &fixture,
                candidate_base,
                candidate_hash,
                active_bytes,
                active_len,
                pre_restore_directory
            );
        } else {
            PV_CHECK(false);
        }
    }
    PV_CHECK(chmod(candidate_base, 0600) == 0);

    if (link(candidate_base, hardlink_path) == 0) {
        security_expect_restore_rejected(
            &fixture,
            hardlink_path,
            candidate_hash,
            active_bytes,
            active_len,
            pre_restore_directory
        );
        PV_CHECK(unlink(hardlink_path) == 0);
    } else {
        PV_CHECK(false);
    }
    if (symlink(candidate_base, symlink_path) == 0) {
        security_expect_restore_rejected(
            &fixture,
            symlink_path,
            candidate_hash,
            active_bytes,
            active_len,
            pre_restore_directory
        );
        PV_CHECK(unlink(symlink_path) == 0);
    } else {
        PV_CHECK(false);
    }
    if (mkdir(directory_path, 0700) == 0) {
        security_expect_restore_rejected(
            &fixture,
            directory_path,
            candidate_hash,
            active_bytes,
            active_len,
            pre_restore_directory
        );
        PV_CHECK(rmdir(directory_path) == 0);
    } else {
        PV_CHECK(false);
    }

    if (mkdir(candidate_parent, 0700) == 0 &&
        security_copy_file(candidate_base, nested_candidate)) {
        if (chmod(candidate_parent, 0775) == 0) {
            security_expect_restore_rejected(
                &fixture,
                nested_candidate,
                candidate_hash,
                active_bytes,
                active_len,
                pre_restore_directory
            );
        } else {
            PV_CHECK(false);
        }
        if (chmod(candidate_parent, 0777) == 0) {
            security_expect_restore_rejected(
                &fixture,
                nested_candidate,
                candidate_hash,
                active_bytes,
                active_len,
                pre_restore_directory
            );
        } else {
            PV_CHECK(false);
        }
        PV_CHECK(chmod(candidate_parent, 0700) == 0);
    } else {
        PV_CHECK(false);
    }

    if (active_bytes != NULL) {
        sodium_memzero(active_bytes, active_len);
        free(active_bytes);
    }
    sodium_memzero(candidate_hash, sizeof candidate_hash);
    security_fixture_destroy(&fixture);
}

static void security_expect_doctor(
    const char *const path,
    const pv_status expected_status,
    const char *const expected_message
)
{
    char message[256] = {0};
    const pv_status status = pv_store_doctor(path, message, sizeof message);

    PV_CHECK_STATUS(status, expected_status);
    PV_CHECK(strcmp(message, expected_message) == 0);
}

static void security_expect_doctor_ok(const char *const path)
{
    static const char prefix[] = "structure OK; format 1.0; encrypted payload ";
    char message[256] = {0};
    const pv_status status = pv_store_doctor(path, message, sizeof message);

    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(strncmp(message, prefix, sizeof prefix - 1U) == 0);
}

static void store_security_doctor_distinguishes_metadata_and_parent_failures(void)
{
    static const mode_t unsafe_modes[] = {0000, 0644, 0660, 0700, 02600, 04600};
    static const char permissions_message[] =
        "vault permissions must be exactly 0400 or 0600";
    static const char hardlink_message[] =
        "vault file has additional hard links";
    static const char path_type_message[] =
        "vault path is not a regular non-symlink file";
    static const char parent_message[] =
        "vault parent directory is unsafe or writable by another user";
    store_security_fixture fixture;
    char hardlink_path[PATH_MAX];
    char symlink_path[PATH_MAX];
    char directory_path[PATH_MAX];
    size_t index;

    if (!security_fixture_init(&fixture)) {
        security_fixture_destroy(&fixture);
        return;
    }
    PV_CHECK(security_make_path(hardlink_path, sizeof hardlink_path, fixture.root, "doctor-hard.pvlt"));
    PV_CHECK(security_make_path(symlink_path, sizeof symlink_path, fixture.root, "doctor-link.pvlt"));
    PV_CHECK(security_make_path(directory_path, sizeof directory_path, fixture.root, "doctor-directory.pvlt"));

    security_expect_doctor_ok(fixture.active);
    if (chmod(fixture.active, 0400) == 0) {
        security_expect_doctor_ok(fixture.active);
    } else {
        PV_CHECK(false);
    }
    PV_CHECK(chmod(fixture.active, 0600) == 0);
    if (chmod(fixture.root, 0755) == 0) {
        security_expect_doctor_ok(fixture.active);
    } else {
        PV_CHECK(false);
    }
    PV_CHECK(chmod(fixture.root, 0700) == 0);

    for (index = 0U; index < sizeof unsafe_modes / sizeof unsafe_modes[0]; ++index) {
        if (chmod(fixture.active, unsafe_modes[index]) == 0) {
            security_expect_doctor(fixture.active, PV_ERR_IO, permissions_message);
        } else {
            PV_CHECK(false);
        }
    }
    PV_CHECK(chmod(fixture.active, 0600) == 0);

    if (link(fixture.active, hardlink_path) == 0) {
        security_expect_doctor(hardlink_path, PV_ERR_IO, hardlink_message);
        PV_CHECK(unlink(hardlink_path) == 0);
    } else {
        PV_CHECK(false);
    }
    if (symlink(fixture.active, symlink_path) == 0) {
        security_expect_doctor(symlink_path, PV_ERR_IO, path_type_message);
        PV_CHECK(unlink(symlink_path) == 0);
    } else {
        PV_CHECK(false);
    }
    if (mkdir(directory_path, 0700) == 0) {
        security_expect_doctor(directory_path, PV_ERR_IO, path_type_message);
        PV_CHECK(rmdir(directory_path) == 0);
    } else {
        PV_CHECK(false);
    }

    if (chmod(fixture.root, 0775) == 0) {
        security_expect_doctor(fixture.active, PV_ERR_IO, parent_message);
    } else {
        PV_CHECK(false);
    }
    if (chmod(fixture.root, 0777) == 0) {
        security_expect_doctor(fixture.active, PV_ERR_IO, parent_message);
    } else {
        PV_CHECK(false);
    }
    PV_CHECK(chmod(fixture.root, 0700) == 0);
    security_fixture_destroy(&fixture);
}

static void store_security_create_refuses_every_preexisting_entry(void)
{
    static const uint8_t marker[] = {0x00U, 'e', 'x', 'i', 's', 't', 'i', 'n', 'g', 0xffU};
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    char directory[PATH_MAX] = {0};
    char symlink_path[PATH_MAX];
    char directory_path[PATH_MAX];
    char regular_path[PATH_MAX];
    char link_target[64];
    struct stat identity = {0};
    pv_vault vault = {0};
    pv_status status;
    ssize_t link_length;
    int fd;

    security_fill_recovery_key(recovery_key);
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        goto cleanup;
    }
    PV_CHECK(security_make_path(symlink_path, sizeof symlink_path, directory, "dangling.pvlt"));
    PV_CHECK(security_make_path(directory_path, sizeof directory_path, directory, "directory.pvlt"));
    PV_CHECK(security_make_path(regular_path, sizeof regular_path, directory, "regular.pvlt"));

    PV_CHECK(symlink("missing-target", symlink_path) == 0);
    PV_CHECK(lstat(symlink_path, &identity) == 0);
    status = pv_store_create(
        symlink_path,
        store_security_password,
        sizeof store_security_password - 1U,
        recovery_key,
        &vault
    );
    PV_CHECK_STATUS(status, PV_ERR_EXISTS);
    PV_CHECK(security_path_identity_matches(symlink_path, &identity));
    pv_model_destroy(&vault);
    link_length = readlink(symlink_path, link_target, sizeof link_target - 1U);
    PV_CHECK(link_length == (ssize_t)(sizeof("missing-target") - 1U));
    if (link_length > 0 && (size_t)link_length < sizeof link_target) {
        link_target[(size_t)link_length] = '\0';
        PV_CHECK(strcmp(link_target, "missing-target") == 0);
    }

    PV_CHECK(mkdir(directory_path, 0700) == 0);
    PV_CHECK(lstat(directory_path, &identity) == 0);
    status = pv_store_create(
        directory_path,
        store_security_password,
        sizeof store_security_password - 1U,
        recovery_key,
        &vault
    );
    PV_CHECK_STATUS(status, PV_ERR_EXISTS);
    PV_CHECK(security_path_identity_matches(directory_path, &identity));
    pv_model_destroy(&vault);

    fd = open(
        regular_path,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0600
    );
    PV_CHECK(fd >= 0);
    if (fd >= 0) {
        PV_CHECK(security_write_all(fd, marker, sizeof marker));
        PV_CHECK(fsync(fd) == 0);
        PV_CHECK(close(fd) == 0);
    }
    PV_CHECK(lstat(regular_path, &identity) == 0);
    status = pv_store_create(
        regular_path,
        store_security_password,
        sizeof store_security_password - 1U,
        recovery_key,
        &vault
    );
    PV_CHECK_STATUS(status, PV_ERR_EXISTS);
    PV_CHECK(security_path_identity_matches(regular_path, &identity));
    pv_model_destroy(&vault);
    PV_CHECK(security_files_equal(regular_path, marker, sizeof marker));

cleanup:
    pv_model_destroy(&vault);
    sodium_memzero(link_target, sizeof link_target);
    sodium_memzero(recovery_key, sizeof recovery_key);
    if (directory[0] != '\0') {
        pv_test_remove_temp_tree(directory);
    }
}

static void store_security_save_refuses_replaced_live_path(void)
{
    store_security_fixture fixture;
    uint8_t title[] = "replacement-test";
    uint8_t secret[] = "synthetic-replacement-secret";
    uint8_t *active_bytes = NULL;
    size_t active_len = 0U;
    char preserved_path[PATH_MAX];
    struct stat active_stat;
    pv_vault vault = {0};
    pv_vault preserved = {0};
    pv_file_header header = {0};
    pv_file_header preserved_header = {0};
    pv_record record;
    pv_status status;
    size_t index;

    if (!security_fixture_init(&fixture)) {
        security_fixture_destroy(&fixture);
        return;
    }
    PV_CHECK(security_make_path(
        preserved_path,
        sizeof preserved_path,
        fixture.root,
        "preserved.pvlt"
    ));
    PV_CHECK(security_read_file(fixture.active, &active_bytes, &active_len));
    status = pv_store_open_password(
        fixture.active,
        store_security_password,
        sizeof store_security_password - 1U,
        &vault,
        &header
    );
    PV_CHECK_STATUS(status, PV_OK);
    sodium_memzero(&record, sizeof record);
    for (index = 0U; index < sizeof record.id; ++index) {
        record.id[index] = (uint8_t)(0xd0U + (uint8_t)index);
    }
    record.title = (pv_slice){title, sizeof title - 1U};
    record.password = (pv_slice){secret, sizeof secret - 1U};
    if (status == PV_OK) {
        status = pv_model_add_record(&vault, &record, NULL);
        PV_CHECK_STATUS(status, PV_OK);
    }
    PV_CHECK(rename(fixture.active, preserved_path) == 0);
    PV_CHECK(symlink("missing-live-target", fixture.active) == 0);
    if (status == PV_OK) {
        status = pv_store_save(&vault, &header, 2U);
        PV_CHECK_STATUS(status, PV_ERR_IO);
    }
    PV_CHECK(lstat(fixture.active, &active_stat) == 0 && S_ISLNK(active_stat.st_mode));
    PV_CHECK(security_files_equal(preserved_path, active_bytes, active_len));
    PV_CHECK(vault.generation == 1U);
    PV_CHECK(vault.dirty);
    status = pv_store_open_recovery(
        preserved_path,
        fixture.recovery_key,
        &preserved,
        &preserved_header
    );
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        PV_CHECK(preserved.generation == 1U);
        PV_CHECK(preserved.record_count == 0U);
    }

    pv_model_destroy(&preserved);
    pv_model_destroy(&vault);
    sodium_memzero(&preserved_header, sizeof preserved_header);
    sodium_memzero(&header, sizeof header);
    sodium_memzero(&record, sizeof record);
    sodium_memzero(secret, sizeof secret);
    if (active_bytes != NULL) {
        sodium_memzero(active_bytes, active_len);
        free(active_bytes);
    }
    security_fixture_destroy(&fixture);
}

static void store_security_read_only_active_opens_but_save_is_nonmutating(void)
{
    store_security_fixture fixture;
    uint8_t title[] = "read-only-active";
    uint8_t secret[] = "synthetic-read-only-secret";
    uint8_t *active_bytes = NULL;
    size_t active_len = 0U;
    struct stat before;
    struct stat after;
    pv_vault vault = {0};
    pv_vault reopened = {0};
    pv_file_header header = {0};
    pv_file_header reopened_header = {0};
    pv_record record;
    pv_status status;
    uint64_t original_generation = 0U;
    size_t index;

    if (!security_fixture_init(&fixture)) {
        security_fixture_destroy(&fixture);
        return;
    }
    PV_CHECK(chmod(fixture.active, 0400) == 0);
    security_expect_open_status(&fixture, fixture.active, PV_OK);
    PV_CHECK(lstat(fixture.active, &before) == 0);
    PV_CHECK((before.st_mode & 07777U) == 0400U);
    PV_CHECK(security_read_file(fixture.active, &active_bytes, &active_len));

    status = pv_store_open_password(
        fixture.active,
        store_security_password,
        sizeof store_security_password - 1U,
        &vault,
        &header
    );
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        original_generation = vault.generation;
        sodium_memzero(&record, sizeof record);
        for (index = 0U; index < sizeof record.id; ++index) {
            record.id[index] = (uint8_t)(0xe0U + (uint8_t)index);
        }
        record.title = (pv_slice){title, sizeof title - 1U};
        record.password = (pv_slice){secret, sizeof secret - 1U};
        status = pv_model_add_record(&vault, &record, NULL);
        PV_CHECK_STATUS(status, PV_OK);
    }
    if (status == PV_OK) {
        PV_CHECK(vault.dirty);
        PV_CHECK(vault.generation == original_generation);
        status = pv_store_save(&vault, &header, 2U);
        PV_CHECK_STATUS(status, PV_ERR_IO);
    }

    PV_CHECK(security_files_equal(fixture.active, active_bytes, active_len));
    PV_CHECK(lstat(fixture.active, &after) == 0);
    if (lstat(fixture.active, &after) == 0) {
        PV_CHECK(after.st_dev == before.st_dev);
        PV_CHECK(after.st_ino == before.st_ino);
        PV_CHECK((after.st_mode & 07777U) == 0400U);
    }
    PV_CHECK(vault.generation == original_generation);
    PV_CHECK(vault.dirty);

    status = pv_store_open_recovery(
        fixture.active,
        fixture.recovery_key,
        &reopened,
        &reopened_header
    );
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        PV_CHECK(reopened.generation == original_generation);
        PV_CHECK(reopened.record_count == 0U);
        PV_CHECK(
            sodium_memcmp(
                reopened.source_hash,
                fixture.active_hash,
                crypto_generichash_BYTES
            ) == 0
        );
    }

    pv_model_destroy(&reopened);
    pv_model_destroy(&vault);
    sodium_memzero(&reopened_header, sizeof reopened_header);
    sodium_memzero(&header, sizeof header);
    sodium_memzero(&record, sizeof record);
    sodium_memzero(secret, sizeof secret);
    if (active_bytes != NULL) {
        sodium_memzero(active_bytes, active_len);
        free(active_bytes);
    }
    security_fixture_destroy(&fixture);
}

static void store_security_read_only_backup_remains_explicit_api_input(void)
{
    store_security_fixture fixture;
    char read_only_backup[PATH_MAX];
    char copied_backup[PATH_MAX];
    char restore_target[PATH_MAX];
    uint8_t *backup_bytes = NULL;
    size_t backup_len = 0U;
    struct stat info;
    pv_status status;

    if (!security_fixture_init(&fixture)) {
        security_fixture_destroy(&fixture);
        return;
    }
    PV_CHECK(security_make_path(
        read_only_backup,
        sizeof read_only_backup,
        fixture.root,
        "read-only-backup.pvlt"
    ));
    PV_CHECK(security_make_path(
        copied_backup,
        sizeof copied_backup,
        fixture.root,
        "copied-from-read-only.pvlt"
    ));
    PV_CHECK(security_make_path(
        restore_target,
        sizeof restore_target,
        fixture.root,
        "restore-target.pvlt"
    ));

    status = pv_store_backup(fixture.active, read_only_backup, fixture.active_hash);
    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(chmod(read_only_backup, 0400) == 0);
    PV_CHECK(security_read_file(read_only_backup, &backup_bytes, &backup_len));
    security_expect_open_status(&fixture, read_only_backup, PV_OK);

    status = pv_store_backup(read_only_backup, copied_backup, fixture.active_hash);
    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(security_files_equal(copied_backup, backup_bytes, backup_len));
    PV_CHECK(lstat(copied_backup, &info) == 0);
    if (lstat(copied_backup, &info) == 0) {
        PV_CHECK((info.st_mode & 07777U) == 0600U);
    }

    PV_CHECK(security_path_absent(restore_target));
    status = pv_store_restore(
        restore_target,
        read_only_backup,
        fixture.active_hash
    );
    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(security_files_equal(restore_target, backup_bytes, backup_len));
    PV_CHECK(lstat(restore_target, &info) == 0);
    if (lstat(restore_target, &info) == 0) {
        PV_CHECK((info.st_mode & 07777U) == 0600U);
    }
    security_expect_open_status(&fixture, restore_target, PV_OK);
    PV_CHECK(lstat(read_only_backup, &info) == 0);
    if (lstat(read_only_backup, &info) == 0) {
        PV_CHECK((info.st_mode & 07777U) == 0400U);
    }

    if (backup_bytes != NULL) {
        sodium_memzero(backup_bytes, backup_len);
        free(backup_bytes);
    }
    security_fixture_destroy(&fixture);
}

static void store_security_restore_refuses_preexisting_nonvault_destination(void)
{
    static const uint8_t marker[] = {
        0x00U, 'c', 'o', 'n', 'c', 'u', 'r', 'r', 'e', 'n', 't', '-',
        'e', 'n', 't', 'r', 'y', 0xffU
    };
    store_security_fixture fixture;
    char destination[PATH_MAX];
    char pre_restore_directory[PATH_MAX];
    struct stat before = {0};
    struct stat after = {0};
    pv_status status;
    int fd;

    if (!security_fixture_init(&fixture)) {
        security_fixture_destroy(&fixture);
        return;
    }
    PV_CHECK(security_make_path(
        destination,
        sizeof destination,
        fixture.root,
        "preexisting-restore-destination.pvlt"
    ));
    PV_CHECK(security_make_path(
        pre_restore_directory,
        sizeof pre_restore_directory,
        fixture.root,
        "backups"
    ));
    fd = open(
        destination,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0600
    );
    PV_CHECK(fd >= 0);
    if (fd >= 0) {
        PV_CHECK(security_write_all(fd, marker, sizeof marker));
        PV_CHECK(fsync(fd) == 0);
        PV_CHECK(close(fd) == 0);
    }
    PV_CHECK(lstat(destination, &before) == 0);
    PV_CHECK(security_path_absent(pre_restore_directory));

    status = pv_store_restore(
        destination,
        fixture.active,
        fixture.active_hash
    );
    PV_CHECK_STATUS(status, PV_ERR_EXISTS);
    PV_CHECK(security_files_equal(destination, marker, sizeof marker));
    PV_CHECK(lstat(destination, &after) == 0);
    if (lstat(destination, &after) == 0) {
        PV_CHECK(after.st_dev == before.st_dev);
        PV_CHECK(after.st_ino == before.st_ino);
        PV_CHECK((after.st_mode & 07777U) == 0600U);
        PV_CHECK(after.st_size == (off_t)sizeof marker);
    }
    PV_CHECK(security_path_absent(pre_restore_directory));

    security_fixture_destroy(&fixture);
}

static void store_security_restore_rejects_authenticated_cross_vault_backup(void)
{
    store_security_fixture vault_b;
    char vault_a_path[PATH_MAX];
    char vault_a_backup[PATH_MAX];
    char pre_restore_directory[PATH_MAX];
    uint8_t vault_a_hash[crypto_generichash_BYTES] = {0};
    uint8_t *vault_b_bytes = NULL;
    size_t vault_b_len = 0U;
    struct stat before = {0};
    struct stat after = {0};
    pv_vault authenticated_a = {0};
    pv_vault authenticated_b = {0};
    pv_file_header authenticated_a_header = {0};
    pv_file_header authenticated_b_header = {0};
    pv_status status;

    if (!security_fixture_init(&vault_b)) {
        security_fixture_destroy(&vault_b);
        return;
    }
    PV_CHECK(security_make_path(
        vault_a_path,
        sizeof vault_a_path,
        vault_b.root,
        "lineage-a.pvlt"
    ));
    PV_CHECK(security_make_path(
        vault_a_backup,
        sizeof vault_a_backup,
        vault_b.root,
        "lineage-a-backup.pvlt"
    ));
    PV_CHECK(security_make_path(
        pre_restore_directory,
        sizeof pre_restore_directory,
        vault_b.root,
        "backups"
    ));
    if (!security_create_snapshot(
            vault_a_path,
            vault_b.recovery_key,
            vault_a_hash
        )) {
        security_fixture_destroy(&vault_b);
        return;
    }
    status = pv_store_backup(vault_a_path, vault_a_backup, vault_a_hash);
    PV_CHECK_STATUS(status, PV_OK);
    status = pv_store_open_password(
        vault_a_backup,
        store_security_password,
        sizeof store_security_password - 1U,
        &authenticated_a,
        &authenticated_a_header
    );
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        PV_CHECK(
            sodium_memcmp(
                authenticated_a.source_hash,
                vault_a_hash,
                crypto_generichash_BYTES
            ) == 0
        );
        status = pv_store_open_recovery(
            vault_b.active,
            vault_b.recovery_key,
            &authenticated_b,
            &authenticated_b_header
        );
        PV_CHECK_STATUS(status, PV_OK);
        if (status == PV_OK) {
            PV_CHECK(
                sodium_memcmp(
                    authenticated_a.vault_id,
                    authenticated_b.vault_id,
                    PV_VAULT_ID_BYTES
                ) != 0
            );
        }
    }
    pv_model_destroy(&authenticated_b);
    pv_model_destroy(&authenticated_a);
    sodium_memzero(&authenticated_b_header, sizeof authenticated_b_header);
    sodium_memzero(&authenticated_a_header, sizeof authenticated_a_header);

    PV_CHECK(security_read_file(vault_b.active, &vault_b_bytes, &vault_b_len));
    PV_CHECK(!security_files_equal(vault_a_backup, vault_b_bytes, vault_b_len));
    PV_CHECK(lstat(vault_b.active, &before) == 0);
    PV_CHECK(security_path_absent(pre_restore_directory));

    status = pv_store_restore(vault_b.active, vault_a_backup, vault_a_hash);
    PV_CHECK_STATUS(status, PV_ERR_AUTH);
    PV_CHECK(security_files_equal(vault_b.active, vault_b_bytes, vault_b_len));
    PV_CHECK(lstat(vault_b.active, &after) == 0);
    if (lstat(vault_b.active, &after) == 0) {
        PV_CHECK(after.st_dev == before.st_dev);
        PV_CHECK(after.st_ino == before.st_ino);
        PV_CHECK((after.st_mode & 07777U) == 0600U);
        PV_CHECK(after.st_size == before.st_size);
    }
    PV_CHECK(security_path_absent(pre_restore_directory));
    security_expect_open_status(&vault_b, vault_b.active, PV_OK);

    sodium_memzero(vault_a_hash, sizeof vault_a_hash);
    if (vault_b_bytes != NULL) {
        sodium_memzero(vault_b_bytes, vault_b_len);
        free(vault_b_bytes);
    }
    security_fixture_destroy(&vault_b);
}

void pv_test_store_security_suite(void)
{
    pv_test_run(
        "store_security.open_rejects_unsafe_snapshot_metadata",
        store_security_open_rejects_unsafe_snapshot_metadata
    );
    pv_test_run(
        "store_security.backup_rejects_unsafe_source_before_destination",
        store_security_backup_rejects_unsafe_source_before_destination
    );
    pv_test_run(
        "store_security.restore_rejects_unsafe_candidate_without_side_effects",
        store_security_restore_rejects_unsafe_candidate_without_side_effects
    );
    pv_test_run(
        "store_security.doctor_distinguishes_metadata_and_parent_failures",
        store_security_doctor_distinguishes_metadata_and_parent_failures
    );
    pv_test_run(
        "store_security.create_refuses_every_preexisting_entry",
        store_security_create_refuses_every_preexisting_entry
    );
    pv_test_run(
        "store_security.save_refuses_replaced_live_path",
        store_security_save_refuses_replaced_live_path
    );
    pv_test_run(
        "store_security.read_only_active_opens_but_save_is_nonmutating",
        store_security_read_only_active_opens_but_save_is_nonmutating
    );
    pv_test_run(
        "store_security.read_only_backup_remains_explicit_api_input",
        store_security_read_only_backup_remains_explicit_api_input
    );
    pv_test_run(
        "store_security.restore_refuses_preexisting_nonvault_destination",
        store_security_restore_refuses_preexisting_nonvault_destination
    );
    pv_test_run(
        "store_security.restore_rejects_authenticated_cross_vault_backup",
        store_security_restore_rejects_authenticated_cross_vault_backup
    );
}
