#define _POSIX_C_SOURCE 200809L

#include "test.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static pv_status add_store_record(
    pv_vault *vault,
    uint8_t *title,
    size_t title_len,
    uint8_t *password,
    size_t password_len,
    uint8_t id_seed
)
{
    pv_record source;
    size_t index;

    (void)memset(&source, 0, sizeof source);
    for (index = 0U; index < sizeof source.id; ++index) {
        source.id[index] = (uint8_t)(id_seed + (uint8_t)index);
    }
    source.title.data = title;
    source.title.len = title_len;
    source.password.data = password;
    source.password.len = password_len;
    return pv_model_add_record(vault, &source, NULL);
}

static bool record_has_password(
    const pv_record *record,
    const uint8_t *password,
    size_t password_len
)
{
    return record->password.len == password_len &&
        sodium_memcmp(record->password.data, password, password_len) == 0;
}

static bool tamper_last_byte(const char *path)
{
    uint8_t byte;
    off_t offset;
    int fd;
    bool success = false;

    fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return false;
    }
    offset = lseek(fd, -1, SEEK_END);
    if (offset >= 0 && pread(fd, &byte, 1U, offset) == 1) {
        byte ^= 0x01U;
        if (pwrite(fd, &byte, 1U, offset) == 1 && fsync(fd) == 0) {
            success = true;
        }
    }
    (void)close(fd);
    return success;
}

static bool truncate_file(const char *path, off_t length)
{
    int fd;
    bool success;

    fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return false;
    }
    success = ftruncate(fd, length) == 0 && fsync(fd) == 0;
    (void)close(fd);
    return success;
}

static bool make_path(char *output, size_t output_len, const char *directory, const char *name)
{
    const int written = snprintf(output, output_len, "%s/%s", directory, name);

    return written > 0 && (size_t)written < output_len;
}

static size_t count_backup_files(const char *directory)
{
    DIR *stream;
    struct dirent *entry;
    size_t count = 0U;

    stream = opendir(directory);
    if (stream == NULL) {
        return SIZE_MAX;
    }
    while ((entry = readdir(stream)) != NULL) {
        const size_t name_len = strlen(entry->d_name);

        if (name_len >= 5U && strcmp(entry->d_name + name_len - 5U, ".pvlt") == 0) {
            ++count;
        }
    }
    (void)closedir(stream);
    return count;
}

static void store_roundtrip_backup_restore_and_integrity(void)
{
    static const uint8_t password[] = {
        's', 't', 'o', 'r', 'e', '-', 'm', 'a', 's', 't', 'e', 'r'
    };
    static const uint8_t wrong_password[] = {'w', 'r', 'o', 'n', 'g'};
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    uint8_t backup_hash[crypto_generichash_BYTES] = {0};
    uint8_t wrong_backup_hash[crypto_generichash_BYTES] = {0};
    uint8_t first_title[] = "first-account";
    uint8_t first_secret[] = {0x00U, 's', 'e', 'c', 'r', 'e', 't', 0xffU};
    uint8_t second_title[] = "second-account";
    uint8_t second_secret[] = "second-secret";
    char directory[PATH_MAX] = {0};
    char vault_path[PATH_MAX];
    char backup_path[PATH_MAX];
    char backup_directory[PATH_MAX];
    char tampered_path[PATH_MAX];
    char truncated_path[PATH_MAX];
    char invalid_restore_path[PATH_MAX];
    char doctor_message[256];
    pv_vault vault;
    pv_vault opened;
    pv_vault stale_writer;
    pv_file_header header;
    pv_file_header stale_header;
    struct stat info;
    pv_status status;
    size_t index;
    size_t backups_before_restore;
    size_t backups_after_restore;

    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        return;
    }
    PV_CHECK(chmod(directory, 0755) == 0);
    PV_CHECK(make_path(vault_path, sizeof vault_path, directory, "vault.pvlt"));
    PV_CHECK(make_path(backup_path, sizeof backup_path, directory, "snapshot.pvlt"));
    PV_CHECK(make_path(backup_directory, sizeof backup_directory, directory, "backups"));
    PV_CHECK(make_path(tampered_path, sizeof tampered_path, directory, "tampered.pvlt"));
    PV_CHECK(make_path(truncated_path, sizeof truncated_path, directory, "truncated.pvlt"));
    PV_CHECK(make_path(invalid_restore_path, sizeof invalid_restore_path, directory, "bad-restore.pvlt"));
    for (index = 0U; index < sizeof recovery_key; ++index) {
        recovery_key[index] = (uint8_t)(0xc0U + index);
    }

    (void)memset(&vault, 0, sizeof vault);
    status = pv_store_create(
        vault_path,
        password,
        sizeof password,
        recovery_key,
        &vault
    );
    PV_CHECK_STATUS(status, PV_OK);
    if (status != PV_OK) {
        pv_model_destroy(&vault);
        sodium_memzero(recovery_key, sizeof recovery_key);
        pv_test_remove_temp_tree(directory);
        return;
    }
    pv_model_destroy(&vault);

    PV_CHECK(stat(directory, &info) == 0);
    if (stat(directory, &info) == 0) {
        PV_CHECK((info.st_mode & 0777U) == 0755U);
    }

    PV_CHECK(stat(vault_path, &info) == 0);
    if (stat(vault_path, &info) == 0) {
        PV_CHECK(S_ISREG(info.st_mode));
        PV_CHECK((info.st_mode & 0777U) == 0600U);
        PV_CHECK(info.st_size > (off_t)PV_FILE_HEADER_LEN);
    }
    status = pv_store_doctor(vault_path, doctor_message, sizeof doctor_message);
    PV_CHECK(status == PV_OK);

    (void)memset(&opened, 0, sizeof opened);
    (void)memset(&header, 0, sizeof header);
    status = pv_store_open_password(
        vault_path,
        password,
        sizeof password,
        &opened,
        &header
    );
    PV_CHECK(status == PV_OK);
    if (status != PV_OK) {
        pv_model_destroy(&opened);
        sodium_memzero(recovery_key, sizeof recovery_key);
        pv_test_remove_temp_tree(directory);
        return;
    }
    (void)memset(&stale_writer, 0, sizeof stale_writer);
    (void)memset(&stale_header, 0, sizeof stale_header);
    status = pv_store_open_password(
        vault_path,
        password,
        sizeof password,
        &stale_writer,
        &stale_header
    );
    PV_CHECK(status == PV_OK);
    if (status != PV_OK) {
        pv_model_destroy(&stale_writer);
        pv_model_destroy(&opened);
        sodium_memzero(recovery_key, sizeof recovery_key);
        pv_test_remove_temp_tree(directory);
        return;
    }
    status = add_store_record(
        &opened,
        first_title,
        sizeof first_title - 1U,
        first_secret,
        sizeof first_secret,
        0x10U
    );
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        status = pv_store_save(&opened, &header, 3U);
        PV_CHECK(status == PV_OK);
    }
    if (status != PV_OK) {
        pv_model_destroy(&stale_writer);
        pv_model_destroy(&opened);
        sodium_memzero(recovery_key, sizeof recovery_key);
        pv_test_remove_temp_tree(directory);
        return;
    }

    status = add_store_record(
        &stale_writer,
        second_title,
        sizeof second_title - 1U,
        second_secret,
        sizeof second_secret - 1U,
        0x70U
    );
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        status = pv_store_save(&stale_writer, &stale_header, 3U);
        PV_CHECK(status == PV_ERR_LOCKED);
    }
    pv_model_destroy(&stale_writer);

    status = pv_store_backup(vault_path, backup_path, NULL);
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        (void)memset(&vault, 0, sizeof vault);
        status = pv_store_open_password(backup_path, password, sizeof password, &vault, &header);
        PV_CHECK(status == PV_OK);
        if (status == PV_OK) {
            (void)memcpy(backup_hash, vault.source_hash, sizeof backup_hash);
        }
        pv_model_destroy(&vault);
    }

    (void)memset(&vault, 0, sizeof vault);
    status = pv_store_open_recovery(vault_path, recovery_key, &vault, &header);
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        PV_CHECK(vault.record_count == 1U);
        if (vault.record_count == 1U) {
            PV_CHECK(pv_slice_equal_cstr(&vault.records[0].title, "first-account", false));
            PV_CHECK(record_has_password(&vault.records[0], first_secret, sizeof first_secret));
        }
    }
    pv_model_destroy(&vault);

    status = add_store_record(
        &opened,
        second_title,
        sizeof second_title - 1U,
        second_secret,
        sizeof second_secret - 1U,
        0x40U
    );
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        status = pv_store_save(&opened, &header, 3U);
        PV_CHECK(status == PV_OK);
    }
    pv_model_destroy(&opened);

    backups_before_restore = count_backup_files(backup_directory);
    PV_CHECK(backups_before_restore != SIZE_MAX);
    status = pv_store_restore(vault_path, backup_path, wrong_backup_hash);
    PV_CHECK(status == PV_ERR_AUTH);
    status = pv_store_restore(vault_path, backup_path, backup_hash);
    PV_CHECK(status == PV_OK);
    backups_after_restore = count_backup_files(backup_directory);
    PV_CHECK(backups_after_restore != SIZE_MAX);
    if (backups_before_restore != SIZE_MAX && backups_after_restore != SIZE_MAX) {
        PV_CHECK(backups_after_restore == backups_before_restore + 1U);
    }
    (void)memset(&vault, 0, sizeof vault);
    status = pv_store_open_password(vault_path, password, sizeof password, &vault, &header);
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        PV_CHECK(vault.record_count == 1U);
        if (vault.record_count == 1U) {
            PV_CHECK(pv_slice_equal_cstr(&vault.records[0].title, "first-account", false));
            PV_CHECK(record_has_password(&vault.records[0], first_secret, sizeof first_secret));
        }
    }
    pv_model_destroy(&vault);

    status = pv_store_backup(vault_path, invalid_restore_path, NULL);
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        PV_CHECK(truncate_file(invalid_restore_path, 32));
        status = pv_store_restore(vault_path, invalid_restore_path, wrong_backup_hash);
        PV_CHECK(status != PV_OK);
    }
    (void)memset(&vault, 0, sizeof vault);
    status = pv_store_open_password(vault_path, password, sizeof password, &vault, &header);
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        PV_CHECK(vault.record_count == 1U);
    }
    pv_model_destroy(&vault);

    (void)memset(&vault, 0, sizeof vault);
    status = pv_store_open_password(
        vault_path,
        wrong_password,
        sizeof wrong_password,
        &vault,
        &header
    );
    PV_CHECK(status == PV_ERR_AUTH);
    pv_model_destroy(&vault);

    status = pv_store_backup(vault_path, tampered_path, NULL);
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        PV_CHECK(tamper_last_byte(tampered_path));
        (void)memset(&vault, 0, sizeof vault);
        status = pv_store_open_password(
            tampered_path,
            password,
            sizeof password,
            &vault,
            &header
        );
        PV_CHECK(status == PV_ERR_AUTH);
        pv_model_destroy(&vault);
    }

    status = pv_store_backup(vault_path, truncated_path, NULL);
    PV_CHECK(status == PV_OK);
    if (status == PV_OK) {
        PV_CHECK(truncate_file(truncated_path, (off_t)PV_FILE_HEADER_LEN - 1));
        (void)memset(&vault, 0, sizeof vault);
        status = pv_store_open_password(
            truncated_path,
            password,
            sizeof password,
            &vault,
            &header
        );
        PV_CHECK(status == PV_ERR_FORMAT || status == PV_ERR_IO);
        pv_model_destroy(&vault);
    }

    PV_CHECK(chmod(directory, 0775) == 0);
    status = pv_store_doctor(vault_path, doctor_message, sizeof doctor_message);
    PV_CHECK(status == PV_ERR_IO);
    PV_CHECK(stat(directory, &info) == 0);
    if (stat(directory, &info) == 0) {
        PV_CHECK((info.st_mode & 0777U) == 0775U);
    }

    sodium_memzero(recovery_key, sizeof recovery_key);
    sodium_memzero(first_secret, sizeof first_secret);
    sodium_memzero(second_secret, sizeof second_secret);
    pv_test_remove_temp_tree(directory);
}

static void store_rejects_shared_writable_parent_without_chmod(void)
{
    static const uint8_t password[] = "synthetic-master";
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES] = {0};
    char directory[PATH_MAX] = {0};
    char vault_path[PATH_MAX];
    struct stat info;
    pv_vault vault = {0};
    pv_status status;

    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') return;
    PV_CHECK(make_path(vault_path, sizeof vault_path, directory, "vault.pvlt"));
    PV_CHECK(chmod(directory, 0775) == 0);
    recovery_key[0] = 1U;
    status = pv_store_create(
        vault_path,
        password,
        sizeof password - 1U,
        recovery_key,
        &vault
    );
    PV_CHECK(status == PV_ERR_IO);
    PV_CHECK(access(vault_path, F_OK) != 0);
    PV_CHECK(stat(directory, &info) == 0);
    if (stat(directory, &info) == 0) {
        PV_CHECK((info.st_mode & 0777U) == 0775U);
    }
    pv_model_destroy(&vault);
    sodium_memzero(recovery_key, sizeof recovery_key);
    pv_test_remove_temp_tree(directory);
}

static bool store_fill_secure_buffer(
    pv_buffer *const buffer,
    const uint8_t *const data,
    const size_t length
)
{
    if (pv_secure_buffer_alloc(buffer, length) != PV_OK) {
        return false;
    }
    memcpy(buffer->data, data, length);
    buffer->len = length;
    return true;
}

static void store_consuming_open_releases_credentials_before_return(void)
{
    static const uint8_t password[] = "consuming-open-master";
    static const uint8_t wrong_password[] = "consuming-open-wrong";
    uint8_t recovery_key[PV_RECOVERY_KEY_BYTES];
    char directory[PATH_MAX] = {0};
    char vault_path[PATH_MAX];
    char missing_path[PATH_MAX];
    pv_buffer credential = {0};
    pv_vault vault = {0};
    pv_file_header header = {0};
    pv_status status;
    size_t index;

    PV_CHECK(pv_test_make_temp_dir(directory, sizeof directory));
    if (directory[0] == '\0') {
        return;
    }
    PV_CHECK(make_path(vault_path, sizeof vault_path, directory, "consume.pvlt"));
    PV_CHECK(make_path(missing_path, sizeof missing_path, directory, "missing.pvlt"));
    for (index = 0U; index < sizeof recovery_key; ++index) {
        recovery_key[index] = (uint8_t)(0x60U + index);
    }
    PV_CHECK(store_fill_secure_buffer(&credential, password, sizeof password - 1U));
    status = pv_store_create_consume(
        vault_path,
        &credential,
        recovery_key,
        &vault
    );
    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(credential.data == NULL && credential.len == 0U && !credential.secure);
    pv_model_destroy(&vault);
    if (status != PV_OK) {
        sodium_memzero(recovery_key, sizeof recovery_key);
        pv_test_remove_temp_tree(directory);
        return;
    }

    PV_CHECK(store_fill_secure_buffer(&credential, password, sizeof password - 1U));
    status = pv_store_open_password_consume(vault_path, &credential, &vault, &header);
    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(credential.data == NULL && credential.len == 0U && !credential.secure);
    pv_model_destroy(&vault);

    PV_CHECK(store_fill_secure_buffer(
        &credential,
        wrong_password,
        sizeof wrong_password - 1U
    ));
    status = pv_store_open_password_consume(vault_path, &credential, &vault, &header);
    PV_CHECK_STATUS(status, PV_ERR_AUTH);
    PV_CHECK(credential.data == NULL && credential.len == 0U && !credential.secure);
    pv_model_destroy(&vault);

    PV_CHECK(store_fill_secure_buffer(&credential, password, sizeof password - 1U));
    status = pv_store_open_password_consume(missing_path, &credential, &vault, &header);
    PV_CHECK(status != PV_OK);
    PV_CHECK(credential.data == NULL && credential.len == 0U && !credential.secure);
    pv_model_destroy(&vault);

    PV_CHECK(store_fill_secure_buffer(&credential, recovery_key, sizeof recovery_key));
    status = pv_store_open_recovery_consume(vault_path, &credential, &vault, &header);
    PV_CHECK_STATUS(status, PV_OK);
    PV_CHECK(credential.data == NULL && credential.len == 0U && !credential.secure);
    pv_model_destroy(&vault);

    pv_buffer_secure_free(&credential);
    sodium_memzero(&header, sizeof header);
    sodium_memzero(recovery_key, sizeof recovery_key);
    pv_test_remove_temp_tree(directory);
}

void pv_test_store_suite(void)
{
    pv_test_run(
        "store.roundtrip_backup_restore_and_integrity",
        store_roundtrip_backup_restore_and_integrity
    );
    pv_test_run(
        "store.rejects_shared_writable_parent_without_chmod",
        store_rejects_shared_writable_parent_without_chmod
    );
    pv_test_run(
        "store.consuming_open_releases_credentials_before_return",
        store_consuming_open_releases_credentials_before_return
    );
}
