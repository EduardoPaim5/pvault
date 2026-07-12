#define _POSIX_C_SOURCE 200809L

#include "test.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef PVAULT_TEST_FAULT_INJECTION
#error "test_store_faults.c requires PVAULT_TEST_FAULT_INJECTION"
#endif

typedef struct pv_fault_point_case {
    const char *name;
    pv_store_fault_point point;
} pv_fault_point_case;

static const uint8_t fault_password[] = "fault-injection-master";

static bool fault_make_path(
    char *const output,
    const size_t output_len,
    const char *const directory,
    const char *const name
)
{
    const int written = snprintf(output, output_len, "%s/%s", directory, name);

    return written > 0 && (size_t)written < output_len;
}

static void fault_fill_recovery_key(uint8_t key[PV_RECOVERY_KEY_BYTES])
{
    size_t index;

    for (index = 0U; index < PV_RECOVERY_KEY_BYTES; ++index) {
        key[index] = (uint8_t)(0x80U + (uint8_t)index);
    }
}

static bool fault_read_header(const char *const path, pv_file_header *const header)
{
    uint8_t bytes[PV_FILE_HEADER_LEN];
    size_t offset = 0U;
    int fd;
    bool success = true;

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
            success = false;
            break;
        }
        offset += (size_t)got;
    }
    if (close(fd) != 0) {
        success = false;
    }
    if (success) {
        success = pv_header_decode(bytes, header) == PV_OK;
    }
    sodium_memzero(bytes, sizeof bytes);
    return success;
}

static bool fault_hash_file(
    const char *const path,
    uint8_t output[crypto_generichash_BYTES]
)
{
    crypto_generichash_state state;
    uint8_t buffer[4096];
    int fd;
    bool success = true;

    sodium_memzero(output, crypto_generichash_BYTES);
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return false;
    }
    if (crypto_generichash_init(&state, NULL, 0U, crypto_generichash_BYTES) != 0) {
        (void)close(fd);
        sodium_memzero(&state, sizeof state);
        return false;
    }
    for (;;) {
        const ssize_t got = read(fd, buffer, sizeof buffer);

        if (got < 0 && errno == EINTR) {
            continue;
        }
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
    if (success && crypto_generichash_final(&state, output, crypto_generichash_BYTES) != 0) {
        success = false;
    }
    if (close(fd) != 0) {
        success = false;
    }
    sodium_memzero(&state, sizeof state);
    sodium_memzero(buffer, sizeof buffer);
    if (!success) {
        sodium_memzero(output, crypto_generichash_BYTES);
    }
    return success;
}

static bool fault_directory_has_temporary_file(const char *const directory)
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

static size_t fault_count_prefixed_files(
    const char *const directory,
    const char *const prefix
)
{
    DIR *stream;
    struct dirent *entry;
    size_t count = 0U;

    stream = opendir(directory);
    if (stream == NULL) {
        return errno == ENOENT ? 0U : SIZE_MAX;
    }
    while ((entry = readdir(stream)) != NULL) {
        if (strncmp(entry->d_name, prefix, strlen(prefix)) == 0) ++count;
    }
    if (closedir(stream) != 0) return SIZE_MAX;
    return count;
}

static bool fault_remove_snapshot_files(const char *const directory)
{
    DIR *stream;
    struct dirent *entry;
    bool success = true;

    stream = opendir(directory);
    if (stream == NULL) return errno == ENOENT;
    while ((entry = readdir(stream)) != NULL) {
        char path[PATH_MAX];
        const size_t name_len = strlen(entry->d_name);
        int written;

        if (entry->d_name[0] == '.' || name_len < 5U ||
            strcmp(entry->d_name + name_len - 5U, ".pvlt") != 0) {
            continue;
        }
        written = snprintf(path, sizeof path, "%s/%s", directory, entry->d_name);
        if (written < 0 || (size_t)written >= sizeof path || unlink(path) != 0) {
            success = false;
        }
    }
    if (closedir(stream) != 0) success = false;
    return success;
}

static bool fault_directory_has_snapshot_hash(
    const char *const directory,
    const char *const prefix,
    const uint8_t expected_hash[crypto_generichash_BYTES]
)
{
    DIR *stream;
    struct dirent *entry;
    bool found = false;

    stream = opendir(directory);
    if (stream == NULL) return false;
    while ((entry = readdir(stream)) != NULL) {
        char path[PATH_MAX];
        uint8_t hash[crypto_generichash_BYTES];
        int written;

        if (strncmp(entry->d_name, prefix, strlen(prefix)) != 0) continue;
        written = snprintf(path, sizeof path, "%s/%s", directory, entry->d_name);
        if (written < 0 || (size_t)written >= sizeof path || !fault_hash_file(path, hash)) {
            continue;
        }
        found = sodium_memcmp(hash, expected_hash, sizeof hash) == 0;
        sodium_memzero(hash, sizeof hash);
        if (found) break;
    }
    (void)closedir(stream);
    return found;
}

static bool fault_snapshot_is_authentic(
    const char *const path,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    const uint8_t expected_hash[crypto_generichash_BYTES],
    const size_t expected_records
)
{
    pv_vault vault = {0};
    pv_file_header header = {0};
    const pv_status status = pv_store_open_recovery(path, recovery_key, &vault, &header);
    const bool matches = status == PV_OK && vault.record_count == expected_records &&
        sodium_memcmp(vault.source_hash, expected_hash, crypto_generichash_BYTES) == 0;

    pv_model_destroy(&vault);
    sodium_memzero(&header, sizeof header);
    return matches;
}

static pv_status fault_add_record(
    pv_vault *const vault,
    uint8_t *const title,
    const size_t title_len,
    uint8_t *const password,
    const size_t password_len,
    const uint8_t id_seed
)
{
    pv_record source;
    size_t index;

    sodium_memzero(&source, sizeof source);
    for (index = 0U; index < sizeof source.id; ++index) {
        source.id[index] = (uint8_t)(id_seed + (uint8_t)index);
    }
    source.title.data = title;
    source.title.len = title_len;
    source.password.data = password;
    source.password.len = password_len;
    return pv_model_add_record(vault, &source, NULL);
}

static bool fault_create_baseline(
    const char *const path,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    pv_vault *const vault,
    pv_file_header *const header
)
{
    pv_status status;

    sodium_memzero(vault, sizeof *vault);
    sodium_memzero(header, sizeof *header);
    pv_store_test_fault_reset();
    status = pv_store_create(
        path,
        fault_password,
        sizeof fault_password - 1U,
        recovery_key,
        vault
    );
    PV_CHECK_STATUS(status, PV_OK);
    if (status != PV_OK) {
        pv_model_destroy(vault);
        return false;
    }
    if (!fault_read_header(path, header)) {
        PV_CHECK(false);
        pv_model_destroy(vault);
        return false;
    }
    return true;
}

static void store_faults_reject_atomic_create_failures(void)
{
    static const pv_fault_point_case cases[] = {
        { "fail-temp-open.pvlt", PV_STORE_FAULT_POINT_ATOMIC_TEMP_OPEN },
        { "fail-header-write.pvlt", PV_STORE_FAULT_POINT_ATOMIC_HEADER_WRITE },
        { "fail-body-write.pvlt", PV_STORE_FAULT_POINT_ATOMIC_BODY_WRITE },
        { "fail-temp-fsync.pvlt", PV_STORE_FAULT_POINT_ATOMIC_TEMP_FSYNC },
        { "fail-temp-close.pvlt", PV_STORE_FAULT_POINT_ATOMIC_TEMP_CLOSE },
        { "fail-rename.pvlt", PV_STORE_FAULT_POINT_ATOMIC_RENAME }
    };
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    char directory[PATH_MAX] = {0};
    size_t index;

    fault_fill_recovery_key(recovery_key);
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        sodium_memzero(recovery_key, sizeof recovery_key);
        return;
    }

    for (index = 0U; index < sizeof cases / sizeof cases[0]; ++index) {
        char path[PATH_MAX];
        pv_vault vault = {0};
        pv_status status;
        uint64_t hits;

        if (!fault_make_path(path, sizeof path, directory, cases[index].name)) {
            PV_CHECK(false);
            continue;
        }
        pv_store_test_fault_reset();
        pv_store_test_fault_point_fail(cases[index].point, EIO);
        status = pv_store_create(
            path,
            fault_password,
            sizeof fault_password - 1U,
            recovery_key,
            &vault
        );
        hits = pv_store_test_fault_point_hit_count(cases[index].point);
        pv_store_test_fault_reset();

        PV_CHECK_STATUS(status, PV_ERR_IO);
        PV_CHECK(hits == 1U);
        PV_CHECK(access(path, F_OK) != 0);
        PV_CHECK(!fault_directory_has_temporary_file(directory));
        pv_model_destroy(&vault);
    }

    pv_store_test_fault_reset();
    sodium_memzero(recovery_key, sizeof recovery_key);
    pv_test_remove_temp_tree(directory);
}

static void store_faults_atomic_update_preserves_existing_snapshot(void)
{
    static const pv_fault_point_case cases[] = {
        { "temp-open", PV_STORE_FAULT_POINT_ATOMIC_TEMP_OPEN },
        { "header-write", PV_STORE_FAULT_POINT_ATOMIC_HEADER_WRITE },
        { "body-write", PV_STORE_FAULT_POINT_ATOMIC_BODY_WRITE },
        { "temp-fsync", PV_STORE_FAULT_POINT_ATOMIC_TEMP_FSYNC },
        { "temp-close", PV_STORE_FAULT_POINT_ATOMIC_TEMP_CLOSE },
        { "rename", PV_STORE_FAULT_POINT_ATOMIC_RENAME }
    };
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    uint8_t expected_hash[crypto_generichash_BYTES];
    uint8_t actual_hash[crypto_generichash_BYTES];
    uint8_t title[] = "fault-record";
    uint8_t secret[] = "not-a-real-secret";
    char directory[PATH_MAX] = {0};
    char path[PATH_MAX];
    char backup_directory[PATH_MAX];
    pv_vault baseline = {0};
    pv_file_header baseline_header = {0};
    size_t index;

    fault_fill_recovery_key(recovery_key);
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        sodium_memzero(recovery_key, sizeof recovery_key);
        return;
    }
    PV_CHECK(fault_make_path(path, sizeof path, directory, "existing.pvlt"));
    PV_CHECK(fault_make_path(
        backup_directory,
        sizeof backup_directory,
        directory,
        "backups"
    ));
    if (!fault_create_baseline(path, recovery_key, &baseline, &baseline_header)) {
        sodium_memzero(recovery_key, sizeof recovery_key);
        pv_test_remove_temp_tree(directory);
        return;
    }
    (void)memcpy(expected_hash, baseline.source_hash, sizeof expected_hash);

    for (index = 0U; index < sizeof cases / sizeof cases[0]; ++index) {
        pv_vault candidate = {0};
        pv_file_header candidate_header = baseline_header;
        pv_status status;
        uint64_t hits;

        status = pv_model_clone(&candidate, &baseline);
        PV_CHECK_STATUS(status, PV_OK);
        if (status == PV_OK) {
            status = fault_add_record(
                &candidate,
                title,
                sizeof title - 1U,
                secret,
                sizeof secret - 1U,
                (uint8_t)(0x20U + (uint8_t)index)
            );
            PV_CHECK_STATUS(status, PV_OK);
        }
        if (status == PV_OK) {
            pv_store_test_fault_reset();
            pv_store_test_fault_point_fail(cases[index].point, EIO);
            status = pv_store_save(&candidate, &candidate_header, 3U);
            hits = pv_store_test_fault_point_hit_count(cases[index].point);
            pv_store_test_fault_reset();

            PV_CHECK_STATUS(status, PV_ERR_IO);
            PV_CHECK(hits == 1U);
            PV_CHECK(candidate.generation == baseline.generation);
            PV_CHECK(fault_hash_file(path, actual_hash));
            PV_CHECK(sodium_memcmp(actual_hash, expected_hash, sizeof expected_hash) == 0);
            PV_CHECK(!fault_directory_has_temporary_file(directory));
            {
                pv_vault verified = {0};
                pv_file_header verified_header = {0};
                const pv_status verify_status = pv_store_open_recovery(
                    path,
                    recovery_key,
                    &verified,
                    &verified_header
                );

                PV_CHECK_STATUS(verify_status, PV_OK);
                if (verify_status == PV_OK) {
                    PV_CHECK(verified.record_count == 0U);
                    PV_CHECK(sodium_memcmp(
                        verified.source_hash,
                        expected_hash,
                        sizeof expected_hash
                    ) == 0);
                }
                pv_model_destroy(&verified);
                sodium_memzero(&verified_header, sizeof verified_header);
            }
            PV_CHECK(fault_remove_snapshot_files(backup_directory));
        }
        pv_model_destroy(&candidate);
        sodium_memzero(&candidate_header, sizeof candidate_header);
    }

    {
        pv_vault opened = {0};
        pv_file_header opened_header = {0};
        const pv_status status = pv_store_open_recovery(
            path,
            recovery_key,
            &opened,
            &opened_header
        );

        PV_CHECK_STATUS(status, PV_OK);
        if (status == PV_OK) {
            PV_CHECK(opened.record_count == 0U);
            PV_CHECK(sodium_memcmp(opened.source_hash, expected_hash, sizeof expected_hash) == 0);
        }
        pv_model_destroy(&opened);
        sodium_memzero(&opened_header, sizeof opened_header);
    }

    pv_store_test_fault_reset();
    pv_model_destroy(&baseline);
    sodium_memzero(&baseline_header, sizeof baseline_header);
    sodium_memzero(recovery_key, sizeof recovery_key);
    sodium_memzero(expected_hash, sizeof expected_hash);
    sodium_memzero(actual_hash, sizeof actual_hash);
    sodium_memzero(secret, sizeof secret);
    pv_test_remove_temp_tree(directory);
}

static void store_faults_report_postcommit_durability(void)
{
    static const pv_fault_point_case cases[] = {
        { "postcommit-dir-open.pvlt", PV_STORE_FAULT_POINT_ATOMIC_DIR_OPEN },
        { "postcommit-dir-fsync.pvlt", PV_STORE_FAULT_POINT_ATOMIC_DIR_FSYNC },
        { "postcommit-readback.pvlt", PV_STORE_FAULT_POINT_SAVE_READBACK }
    };
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    char directory[PATH_MAX] = {0};
    size_t index;

    fault_fill_recovery_key(recovery_key);
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        sodium_memzero(recovery_key, sizeof recovery_key);
        return;
    }

    for (index = 0U; index < sizeof cases / sizeof cases[0]; ++index) {
        char path[PATH_MAX];
        pv_vault created = {0};
        pv_vault opened = {0};
        pv_file_header header = {0};
        pv_status status;
        uint64_t hits;

        if (!fault_make_path(path, sizeof path, directory, cases[index].name)) {
            PV_CHECK(false);
            continue;
        }
        pv_store_test_fault_reset();
        pv_store_test_fault_point_fail(cases[index].point, EIO);
        status = pv_store_create(
            path,
            fault_password,
            sizeof fault_password - 1U,
            recovery_key,
            &created
        );
        hits = pv_store_test_fault_point_hit_count(cases[index].point);
        pv_store_test_fault_reset();

        PV_CHECK_STATUS(status, PV_ERR_DURABILITY);
        PV_CHECK(hits == 1U);
        PV_CHECK(access(path, F_OK) == 0);
        PV_CHECK(!fault_directory_has_temporary_file(directory));
        pv_model_destroy(&created);

        status = pv_store_open_recovery(path, recovery_key, &opened, &header);
        PV_CHECK_STATUS(status, PV_OK);
        if (status == PV_OK) {
            PV_CHECK(opened.generation == 1U);
            PV_CHECK(opened.record_count == 0U);
        }
        pv_model_destroy(&opened);
        sodium_memzero(&header, sizeof header);
    }

    pv_store_test_fault_reset();
    sodium_memzero(recovery_key, sizeof recovery_key);
    pv_test_remove_temp_tree(directory);
}

static void store_faults_public_backup_removes_partial_snapshot(void)
{
    static const pv_fault_point_case cases[] = {
        { "backup-open.pvlt", PV_STORE_FAULT_POINT_SNAPSHOT_OPEN },
        { "backup-write.pvlt", PV_STORE_FAULT_POINT_SNAPSHOT_WRITE },
        { "backup-fsync.pvlt", PV_STORE_FAULT_POINT_SNAPSHOT_FSYNC },
        { "backup-parent-fsync.pvlt", PV_STORE_FAULT_POINT_SNAPSHOT_PARENT_FSYNC }
    };
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    uint8_t baseline_hash[crypto_generichash_BYTES];
    char directory[PATH_MAX] = {0};
    char path[PATH_MAX];
    pv_vault baseline = {0};
    pv_file_header header = {0};
    size_t index;

    fault_fill_recovery_key(recovery_key);
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        sodium_memzero(recovery_key, sizeof recovery_key);
        return;
    }
    PV_CHECK(fault_make_path(path, sizeof path, directory, "backup-source.pvlt"));
    if (!fault_create_baseline(path, recovery_key, &baseline, &header)) {
        sodium_memzero(recovery_key, sizeof recovery_key);
        pv_test_remove_temp_tree(directory);
        return;
    }
    (void)memcpy(baseline_hash, baseline.source_hash, sizeof baseline_hash);

    for (index = 0U; index < sizeof cases / sizeof cases[0]; ++index) {
        char output[PATH_MAX];
        pv_status status;
        uint64_t hits;

        PV_CHECK(fault_make_path(output, sizeof output, directory, cases[index].name));
        pv_store_test_fault_reset();
        pv_store_test_fault_point_fail(cases[index].point, EIO);
        status = pv_store_backup(path, output, baseline_hash);
        hits = pv_store_test_fault_point_hit_count(cases[index].point);
        pv_store_test_fault_reset();

        PV_CHECK_STATUS(status, PV_ERR_IO);
        PV_CHECK(hits == 1U);
        PV_CHECK(access(output, F_OK) != 0);
        PV_CHECK(fault_snapshot_is_authentic(path, recovery_key, baseline_hash, 0U));
    }

    pv_model_destroy(&baseline);
    sodium_memzero(&header, sizeof header);
    sodium_memzero(baseline_hash, sizeof baseline_hash);
    sodium_memzero(recovery_key, sizeof recovery_key);
    pv_test_remove_temp_tree(directory);
}

static void store_faults_restore_preserves_active_snapshot(void)
{
    static const pv_fault_point_case copy_cases[] = {
        { "copy-open", PV_STORE_FAULT_POINT_COPY_DEST_OPEN },
        { "copy-write", PV_STORE_FAULT_POINT_COPY_WRITE },
        { "copy-fsync", PV_STORE_FAULT_POINT_COPY_FSYNC },
        { "copy-parent-fsync", PV_STORE_FAULT_POINT_COPY_PARENT_FSYNC }
    };
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    uint8_t active_hash[crypto_generichash_BYTES];
    uint8_t source_hash[crypto_generichash_BYTES];
    uint8_t title[] = "restore-source";
    uint8_t secret[] = "synthetic-secret";
    char directory[PATH_MAX] = {0};
    char active_path[PATH_MAX];
    char source_path[PATH_MAX];
    char backup_directory[PATH_MAX];
    pv_vault active = {0};
    pv_vault source = {0};
    pv_file_header active_header = {0};
    pv_file_header source_header = {0};
    size_t index;

    fault_fill_recovery_key(recovery_key);
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        sodium_memzero(recovery_key, sizeof recovery_key);
        return;
    }
    PV_CHECK(fault_make_path(active_path, sizeof active_path, directory, "restore-active.pvlt"));
    PV_CHECK(fault_make_path(source_path, sizeof source_path, directory, "restore-source.pvlt"));
    PV_CHECK(fault_make_path(
        backup_directory,
        sizeof backup_directory,
        directory,
        "backups"
    ));
    if (!fault_create_baseline(active_path, recovery_key, &active, &active_header) ||
        !fault_create_baseline(source_path, recovery_key, &source, &source_header)) {
        pv_model_destroy(&active);
        pv_model_destroy(&source);
        sodium_memzero(recovery_key, sizeof recovery_key);
        pv_test_remove_temp_tree(directory);
        return;
    }
    (void)memcpy(active_hash, active.source_hash, sizeof active_hash);
    PV_CHECK_STATUS(
        fault_add_record(
            &source,
            title,
            sizeof title - 1U,
            secret,
            sizeof secret - 1U,
            0x60U
        ),
        PV_OK
    );
    PV_CHECK_STATUS(pv_store_save(&source, &source_header, 3U), PV_OK);
    (void)memcpy(source_hash, source.source_hash, sizeof source_hash);

    for (index = 0U; index < sizeof copy_cases / sizeof copy_cases[0]; ++index) {
        const size_t before = fault_count_prefixed_files(backup_directory, "pre-restore-");
        pv_status status;
        uint64_t hits;
        size_t after;

        PV_CHECK(before != SIZE_MAX);
        pv_store_test_fault_reset();
        pv_store_test_fault_point_fail(copy_cases[index].point, EIO);
        status = pv_store_restore(active_path, source_path, source_hash);
        hits = pv_store_test_fault_point_hit_count(copy_cases[index].point);
        pv_store_test_fault_reset();
        after = fault_count_prefixed_files(backup_directory, "pre-restore-");

        PV_CHECK_STATUS(status, PV_ERR_IO);
        PV_CHECK(hits == 1U);
        PV_CHECK(after == before);
        PV_CHECK(fault_snapshot_is_authentic(active_path, recovery_key, active_hash, 0U));
    }

    {
        const size_t before = fault_count_prefixed_files(backup_directory, "pre-restore-");
        pv_status status;
        uint64_t hits;
        size_t after;

        PV_CHECK(before != SIZE_MAX);
        pv_store_test_fault_reset();
        pv_store_test_fault_point_fail(PV_STORE_FAULT_POINT_ATOMIC_RENAME, EIO);
        status = pv_store_restore(active_path, source_path, source_hash);
        hits = pv_store_test_fault_point_hit_count(PV_STORE_FAULT_POINT_ATOMIC_RENAME);
        pv_store_test_fault_reset();
        after = fault_count_prefixed_files(backup_directory, "pre-restore-");

        PV_CHECK_STATUS(status, PV_ERR_IO);
        PV_CHECK(hits == 1U);
        PV_CHECK(before != SIZE_MAX && after == before + 1U);
        PV_CHECK(fault_snapshot_is_authentic(active_path, recovery_key, active_hash, 0U));
        PV_CHECK(fault_directory_has_snapshot_hash(
            backup_directory,
            "pre-restore-",
            active_hash
        ));
        PV_CHECK(!fault_directory_has_temporary_file(directory));
    }

    {
        const size_t before = fault_count_prefixed_files(backup_directory, "pre-restore-");
        pv_status status;
        uint64_t hits;
        size_t after;

        PV_CHECK(before != SIZE_MAX);
        pv_store_test_fault_reset();
        pv_store_test_fault_point_fail(PV_STORE_FAULT_POINT_ATOMIC_DIR_FSYNC, EIO);
        status = pv_store_restore(active_path, source_path, source_hash);
        hits = pv_store_test_fault_point_hit_count(PV_STORE_FAULT_POINT_ATOMIC_DIR_FSYNC);
        pv_store_test_fault_reset();
        after = fault_count_prefixed_files(backup_directory, "pre-restore-");

        PV_CHECK_STATUS(status, PV_ERR_DURABILITY);
        PV_CHECK(hits == 1U);
        PV_CHECK(before != SIZE_MAX && after == before + 1U);
        PV_CHECK(fault_snapshot_is_authentic(active_path, recovery_key, source_hash, 1U));
        PV_CHECK(!fault_directory_has_temporary_file(directory));
    }

    pv_store_test_fault_reset();
    pv_model_destroy(&active);
    pv_model_destroy(&source);
    sodium_memzero(&active_header, sizeof active_header);
    sodium_memzero(&source_header, sizeof source_header);
    sodium_memzero(active_hash, sizeof active_hash);
    sodium_memzero(source_hash, sizeof source_hash);
    sodium_memzero(recovery_key, sizeof recovery_key);
    sodium_memzero(secret, sizeof secret);
    pv_test_remove_temp_tree(directory);
}

static void store_faults_retry_short_write_and_eintr(void)
{
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    char directory[PATH_MAX] = {0};
    char path[PATH_MAX];
    pv_vault created = {0};
    pv_vault opened = {0};
    pv_file_header header = {0};
    pv_status status;
    uint64_t write_calls;

    fault_fill_recovery_key(recovery_key);
    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        sodium_memzero(recovery_key, sizeof recovery_key);
        return;
    }
    PV_CHECK(fault_make_path(path, sizeof path, directory, "short-write.pvlt"));

    pv_store_test_fault_reset();
    pv_store_test_fault_short_write(1U, 1U);
    status = pv_store_create(
        path,
        fault_password,
        sizeof fault_password - 1U,
        recovery_key,
        &created
    );
    write_calls = pv_store_test_fault_call_count(PV_STORE_FAULT_WRITE);
    pv_store_test_fault_reset();

    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(write_calls >= 3U);
    PV_CHECK(!fault_directory_has_temporary_file(directory));
    pv_model_destroy(&created);

    status = pv_store_open_recovery(path, recovery_key, &opened, &header);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        PV_CHECK(opened.generation == 1U);
        PV_CHECK(opened.record_count == 0U);
    }
    pv_model_destroy(&opened);
    sodium_memzero(&header, sizeof header);

    PV_CHECK(fault_make_path(path, sizeof path, directory, "interrupted-write.pvlt"));
    pv_store_test_fault_reset();
    pv_store_test_fault_fail(PV_STORE_FAULT_WRITE, 1U, EINTR);
    status = pv_store_create(
        path,
        fault_password,
        sizeof fault_password - 1U,
        recovery_key,
        &created
    );
    write_calls = pv_store_test_fault_call_count(PV_STORE_FAULT_WRITE);
    pv_store_test_fault_reset();

    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(write_calls >= 3U);
    PV_CHECK(!fault_directory_has_temporary_file(directory));
    pv_model_destroy(&created);

    status = pv_store_open_recovery(path, recovery_key, &opened, &header);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        PV_CHECK(opened.generation == 1U);
        PV_CHECK(opened.record_count == 0U);
    }

    pv_model_destroy(&opened);
    sodium_memzero(&header, sizeof header);
    sodium_memzero(recovery_key, sizeof recovery_key);
    pv_test_remove_temp_tree(directory);
}

void pv_test_store_fault_suite(void)
{
    pv_test_run(
        "store_faults.reject_atomic_create_failures",
        store_faults_reject_atomic_create_failures
    );
    pv_test_run(
        "store_faults.atomic_update_preserves_existing_snapshot",
        store_faults_atomic_update_preserves_existing_snapshot
    );
    pv_test_run(
        "store_faults.report_postcommit_durability",
        store_faults_report_postcommit_durability
    );
    pv_test_run(
        "store_faults.public_backup_removes_partial_snapshot",
        store_faults_public_backup_removes_partial_snapshot
    );
    pv_test_run(
        "store_faults.restore_preserves_active_snapshot",
        store_faults_restore_preserves_active_snapshot
    );
    pv_test_run(
        "store_faults.retry_short_write_and_eintr",
        store_faults_retry_short_write_and_eintr
    );
}
