#define _POSIX_C_SOURCE 200809L

#include "test.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct config_saved_environment {
    char *xdg_config_home;
    char *xdg_data_home;
    char *home;
    bool had_xdg_config_home;
    bool had_xdg_data_home;
    bool had_home;
} config_saved_environment;

typedef struct config_fixture {
    char root[PATH_MAX];
    char config_home[PATH_MAX];
    char config_parent[PATH_MAX];
    char config_path[PATH_MAX];
    char data_home[PATH_MAX];
    char home[PATH_MAX];
    config_saved_environment saved_environment;
    bool environment_saved;
} config_fixture;

static const uint8_t config_valid_text[] =
    "vault_path=/tmp/pvault-config-synthetic.pvlt\n"
    "clipboard_ttl_seconds=17\n"
    "session_idle_seconds=901\n"
    "backup_retention=37\n"
    "picker=rofi\n";

static bool config_make_path(
    char *const output,
    const size_t output_len,
    const char *const parent,
    const char *const name
)
{
    const int written = snprintf(output, output_len, "%s/%s", parent, name);

    return written > 0 && (size_t)written < output_len;
}

static bool config_duplicate_environment(
    const char *const name,
    char **const saved_value,
    bool *const was_present
)
{
    const char *const value = getenv(name);

    *saved_value = NULL;
    *was_present = value != NULL;
    if (value != NULL) {
        *saved_value = strdup(value);
        if (*saved_value == NULL) {
            return false;
        }
    }
    return true;
}

static void config_restore_environment_value(
    const char *const name,
    char **const saved_value,
    const bool was_present
)
{
    if (was_present) {
        (void)setenv(name, *saved_value, 1);
    } else {
        (void)unsetenv(name);
    }
    free(*saved_value);
    *saved_value = NULL;
}

static void config_fixture_destroy(config_fixture *const fixture)
{
    if (fixture == NULL) {
        return;
    }
    if (fixture->environment_saved) {
        config_restore_environment_value(
            "XDG_CONFIG_HOME",
            &fixture->saved_environment.xdg_config_home,
            fixture->saved_environment.had_xdg_config_home
        );
        config_restore_environment_value(
            "XDG_DATA_HOME",
            &fixture->saved_environment.xdg_data_home,
            fixture->saved_environment.had_xdg_data_home
        );
        config_restore_environment_value(
            "HOME",
            &fixture->saved_environment.home,
            fixture->saved_environment.had_home
        );
    }
    pv_test_remove_temp_tree(fixture->root);
    memset(fixture, 0, sizeof(*fixture));
}

static bool config_fixture_init(config_fixture *const fixture)
{
    bool saved_config = false;
    bool saved_data = false;
    bool saved_home = false;

    if (fixture == NULL) {
        return false;
    }
    memset(fixture, 0, sizeof(*fixture));
    if (!config_duplicate_environment(
            "XDG_CONFIG_HOME",
            &fixture->saved_environment.xdg_config_home,
            &fixture->saved_environment.had_xdg_config_home
        )) {
        goto fail;
    }
    saved_config = true;
    if (!config_duplicate_environment(
            "XDG_DATA_HOME",
            &fixture->saved_environment.xdg_data_home,
            &fixture->saved_environment.had_xdg_data_home
        )) {
        goto fail;
    }
    saved_data = true;
    if (!config_duplicate_environment(
            "HOME",
            &fixture->saved_environment.home,
            &fixture->saved_environment.had_home
        )) {
        goto fail;
    }
    saved_home = true;
    fixture->environment_saved = true;

    if (!pv_test_make_temp_dir(fixture->root, sizeof(fixture->root)) ||
        !config_make_path(
            fixture->config_home,
            sizeof(fixture->config_home),
            fixture->root,
            "config-home"
        ) ||
        !config_make_path(
            fixture->config_parent,
            sizeof(fixture->config_parent),
            fixture->config_home,
            "pvault"
        ) ||
        !config_make_path(
            fixture->config_path,
            sizeof(fixture->config_path),
            fixture->config_parent,
            "config"
        ) ||
        !config_make_path(
            fixture->data_home,
            sizeof(fixture->data_home),
            fixture->root,
            "data-home"
        ) ||
        !config_make_path(fixture->home, sizeof(fixture->home), fixture->root, "home") ||
        mkdir(fixture->config_home, 0700) != 0 ||
        mkdir(fixture->config_parent, 0700) != 0 ||
        mkdir(fixture->data_home, 0700) != 0 ||
        mkdir(fixture->home, 0700) != 0 ||
        setenv("XDG_CONFIG_HOME", fixture->config_home, 1) != 0 ||
        setenv("XDG_DATA_HOME", fixture->data_home, 1) != 0 ||
        setenv("HOME", fixture->home, 1) != 0) {
        config_fixture_destroy(fixture);
        return false;
    }
    return true;

fail:
    if (saved_home) {
        free(fixture->saved_environment.home);
    }
    if (saved_data) {
        free(fixture->saved_environment.xdg_data_home);
    }
    if (saved_config) {
        free(fixture->saved_environment.xdg_config_home);
    }
    memset(fixture, 0, sizeof(*fixture));
    return false;
}

static bool config_write_all(const int fd, const uint8_t *data, size_t length)
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

static bool config_write_bytes(
    const char *const path,
    const uint8_t *const data,
    const size_t length,
    const mode_t mode
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
    success = config_write_all(fd, data, length);
    if (success && fchmod(fd, mode) != 0) {
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

static bool config_write_text(
    const char *const path,
    const char *const text,
    const mode_t mode
)
{
    return config_write_bytes(path, (const uint8_t *)text, strlen(text), mode);
}

static void config_set_sentinel(pv_config *const config)
{
    memset(config, 0, sizeof(*config));
    (void)memcpy(config->vault_path, "/sentinel/unchanged.pvlt", 25U);
    config->clipboard_ttl = 271U;
    config->session_ttl = 27001U;
    config->backup_retention = 997U;
    config->picker_rofi = true;
}

static void config_expect_rejected(
    const pv_status expected_status,
    const bool expect_unchanged
)
{
    pv_config config;
    pv_config before;
    pv_status status;

    config_set_sentinel(&config);
    before = config;
    status = pv_config_load(&config);
    PV_CHECK_STATUS(status, expected_status);
    if (expect_unchanged) {
        PV_CHECK(memcmp(&config, &before, sizeof(config)) == 0);
    }
}

static void config_absent_uses_defaults(void)
{
    config_fixture fixture;
    pv_config config;
    char expected_vault[PATH_MAX];
    int written;
    pv_status status;

    PV_CHECK(config_fixture_init(&fixture));
    if (fixture.root[0] == '\0') {
        return;
    }
    memset(&config, 0xa5, sizeof(config));
    status = pv_config_load(&config);
    PV_CHECK_STATUS(status, PV_OK);
    written = snprintf(
        expected_vault,
        sizeof(expected_vault),
        "%s/pvault/vault.pvlt",
        fixture.data_home
    );
    PV_CHECK(written > 0 && (size_t)written < sizeof(expected_vault));
    if (written > 0 && (size_t)written < sizeof(expected_vault)) {
        PV_CHECK(strcmp(config.vault_path, expected_vault) == 0);
    }
    PV_CHECK(config.clipboard_ttl == PV_DEFAULT_CLIPBOARD_TTL);
    PV_CHECK(config.session_ttl == PV_DEFAULT_SESSION_TTL);
    PV_CHECK(config.backup_retention == PV_DEFAULT_BACKUP_RETENTION);
    PV_CHECK(!config.picker_rofi);
    config_fixture_destroy(&fixture);
}

static void config_accepts_private_regular_files(void)
{
    static const mode_t accepted_modes[] = { 0600, 0400 };
    config_fixture fixture;
    size_t index;

    PV_CHECK(config_fixture_init(&fixture));
    if (fixture.root[0] == '\0') {
        return;
    }
    for (index = 0U; index < sizeof(accepted_modes) / sizeof(accepted_modes[0]); ++index) {
        pv_config config;
        pv_status status;

        PV_CHECK(config_write_bytes(
            fixture.config_path,
            config_valid_text,
            sizeof(config_valid_text) - 1U,
            accepted_modes[index]
        ));
        status = pv_config_load(&config);
        PV_CHECK_STATUS(status, PV_OK);
        if (status == PV_OK) {
            PV_CHECK(strcmp(config.vault_path, "/tmp/pvault-config-synthetic.pvlt") == 0);
            PV_CHECK(config.clipboard_ttl == 17U);
            PV_CHECK(config.session_ttl == 901U);
            PV_CHECK(config.backup_retention == 37U);
            PV_CHECK(config.picker_rofi);
        }
        PV_CHECK(unlink(fixture.config_path) == 0);
    }
    PV_CHECK(chmod(fixture.config_parent, 0755) == 0);
    PV_CHECK(config_write_bytes(
        fixture.config_path,
        config_valid_text,
        sizeof(config_valid_text) - 1U,
        0600
    ));
    {
        pv_config config;

        PV_CHECK_STATUS(pv_config_load(&config), PV_OK);
    }
    config_fixture_destroy(&fixture);
}

static void config_rejects_non_regular_and_linked_objects(void)
{
    config_fixture fixture;
    char target[PATH_MAX];

    PV_CHECK(config_fixture_init(&fixture));
    if (fixture.root[0] == '\0') {
        return;
    }
    PV_CHECK(config_make_path(target, sizeof(target), fixture.config_parent, "target"));
    PV_CHECK(config_write_bytes(
        target,
        config_valid_text,
        sizeof(config_valid_text) - 1U,
        0600
    ));

    PV_CHECK(symlink("target", fixture.config_path) == 0);
    config_expect_rejected(PV_ERR_IO, true);
    PV_CHECK(unlink(fixture.config_path) == 0);

    PV_CHECK(link(target, fixture.config_path) == 0);
    config_expect_rejected(PV_ERR_IO, true);
    PV_CHECK(unlink(fixture.config_path) == 0);

    PV_CHECK(mkdir(fixture.config_path, 0700) == 0);
    config_expect_rejected(PV_ERR_IO, true);
    PV_CHECK(rmdir(fixture.config_path) == 0);

    PV_CHECK(mkfifo(fixture.config_path, 0600) == 0);
    config_expect_rejected(PV_ERR_IO, true);
    PV_CHECK(unlink(fixture.config_path) == 0);

    config_fixture_destroy(&fixture);
}

static void config_rejects_unsafe_file_modes_and_owner(void)
{
    static const mode_t rejected_modes[] = {
        0000, 0200, 0644, 0660, 0700, 02600, 04600
    };
    config_fixture fixture;
    size_t index;

    PV_CHECK(config_fixture_init(&fixture));
    if (fixture.root[0] == '\0') {
        return;
    }
    PV_CHECK(config_write_bytes(
        fixture.config_path,
        config_valid_text,
        sizeof(config_valid_text) - 1U,
        0600
    ));
    for (index = 0U; index < sizeof(rejected_modes) / sizeof(rejected_modes[0]); ++index) {
        PV_CHECK(chmod(fixture.config_path, rejected_modes[index]) == 0);
        config_expect_rejected(PV_ERR_IO, true);
    }
    if (geteuid() == 0) {
        PV_CHECK(chmod(fixture.config_path, 0600) == 0);
        PV_CHECK(chown(fixture.config_path, 1U, (gid_t)-1) == 0);
        config_expect_rejected(PV_ERR_IO, true);
    }
    config_fixture_destroy(&fixture);
}

static void config_rejects_unsafe_parent(void)
{
    config_fixture fixture;
    char actual_parent[PATH_MAX];
    char actual_config[PATH_MAX];

    PV_CHECK(config_fixture_init(&fixture));
    if (fixture.root[0] == '\0') {
        return;
    }
    PV_CHECK(config_write_bytes(
        fixture.config_path,
        config_valid_text,
        sizeof(config_valid_text) - 1U,
        0600
    ));
    PV_CHECK(chmod(fixture.config_parent, 0770) == 0);
    config_expect_rejected(PV_ERR_IO, true);
    PV_CHECK(chmod(fixture.config_parent, 0777) == 0);
    config_expect_rejected(PV_ERR_IO, true);
    PV_CHECK(chmod(fixture.config_parent, 0700) == 0);
    if (geteuid() == 0) {
        PV_CHECK(chown(fixture.config_parent, 1U, (gid_t)-1) == 0);
        config_expect_rejected(PV_ERR_IO, true);
        PV_CHECK(chown(fixture.config_parent, 0U, (gid_t)-1) == 0);
    }
    PV_CHECK(unlink(fixture.config_path) == 0);

    PV_CHECK(rmdir(fixture.config_parent) == 0);
    PV_CHECK(config_make_path(actual_parent, sizeof(actual_parent), fixture.config_home, "actual"));
    PV_CHECK(config_make_path(actual_config, sizeof(actual_config), actual_parent, "config"));
    PV_CHECK(mkdir(actual_parent, 0700) == 0);
    PV_CHECK(config_write_bytes(
        actual_config,
        config_valid_text,
        sizeof(config_valid_text) - 1U,
        0600
    ));
    PV_CHECK(symlink("actual", fixture.config_parent) == 0);
    config_expect_rejected(PV_ERR_IO, true);

    config_fixture_destroy(&fixture);
}

static void config_accepts_crlf(void)
{
    static const char crlf[] =
        "clipboard_ttl_seconds=19\r\n"
        "session_idle_seconds=902\r\n"
        "backup_retention=38\r\n"
        "picker=rofi\r\n";
    config_fixture fixture;
    pv_config config;
    pv_status status;

    PV_CHECK(config_fixture_init(&fixture));
    if (fixture.root[0] == '\0') {
        return;
    }
    PV_CHECK(config_write_text(fixture.config_path, crlf, 0400));
    status = pv_config_load(&config);
    PV_CHECK_STATUS(status, PV_OK);
    if (status == PV_OK) {
        PV_CHECK(config.clipboard_ttl == 19U);
        PV_CHECK(config.session_ttl == 902U);
        PV_CHECK(config.backup_retention == 38U);
        PV_CHECK(config.picker_rofi);
    }
    config_fixture_destroy(&fixture);
}

static void config_rejects_duplicate_nul_and_size_limits(void)
{
    static const uint8_t embedded_nul[] =
        "clipboard_ttl_seconds=10\0picker=rofi\n";
    static const char duplicate[] =
        "clipboard_ttl_seconds=10\nclipboard_ttl_seconds=11\n";
    config_fixture fixture;
    uint8_t *long_line = NULL;
    size_t long_length = (size_t)PATH_MAX + 512U;
    uint8_t *oversized_file = NULL;
    size_t oversized_length = 64U * 1024U + 1U;

    PV_CHECK(config_fixture_init(&fixture));
    if (fixture.root[0] == '\0') {
        return;
    }

    PV_CHECK(config_write_text(fixture.config_path, duplicate, 0600));
    config_expect_rejected(PV_ERR_FORMAT, true);
    PV_CHECK(unlink(fixture.config_path) == 0);

    PV_CHECK(config_write_bytes(
        fixture.config_path,
        embedded_nul,
        sizeof(embedded_nul) - 1U,
        0600
    ));
    config_expect_rejected(PV_ERR_FORMAT, true);
    PV_CHECK(unlink(fixture.config_path) == 0);

    long_line = malloc(long_length);
    PV_CHECK(long_line != NULL);
    if (long_line != NULL) {
        static const char prefix[] = "picker=internal";

        memset(long_line, ' ', long_length);
        (void)memcpy(long_line, prefix, sizeof(prefix) - 1U);
        long_line[long_length - 1U] = (uint8_t)'\n';
        PV_CHECK(config_write_bytes(fixture.config_path, long_line, long_length, 0600));
        config_expect_rejected(PV_ERR_LIMIT, true);
        PV_CHECK(unlink(fixture.config_path) == 0);
        sodium_memzero(long_line, long_length);
        free(long_line);
    }

    oversized_file = malloc(oversized_length);
    PV_CHECK(oversized_file != NULL);
    if (oversized_file != NULL) {
        memset(oversized_file, '#', oversized_length);
        PV_CHECK(config_write_bytes(
            fixture.config_path,
            oversized_file,
            oversized_length,
            0600
        ));
        config_expect_rejected(PV_ERR_LIMIT, true);
        PV_CHECK(unlink(fixture.config_path) == 0);
        sodium_memzero(oversized_file, oversized_length);
        free(oversized_file);
    }

    config_fixture_destroy(&fixture);
}

static void config_parse_is_transactional_on_error(void)
{
    static const char invalid_after_valid[] =
        "vault_path=/tmp/partially-applied.pvlt\n"
        "clipboard_ttl_seconds=42\n"
        "picker=external-shell\n";
    config_fixture fixture;

    PV_CHECK(config_fixture_init(&fixture));
    if (fixture.root[0] == '\0') {
        return;
    }
    PV_CHECK(config_write_text(fixture.config_path, invalid_after_valid, 0600));
    config_expect_rejected(PV_ERR_FORMAT, true);
    config_fixture_destroy(&fixture);
}

void pv_test_config_suite(void)
{
    pv_test_run("config.absent_uses_defaults", config_absent_uses_defaults);
    pv_test_run(
        "config.accepts_private_regular_files",
        config_accepts_private_regular_files
    );
    pv_test_run(
        "config.rejects_non_regular_and_linked_objects",
        config_rejects_non_regular_and_linked_objects
    );
    pv_test_run(
        "config.rejects_unsafe_file_modes_and_owner",
        config_rejects_unsafe_file_modes_and_owner
    );
    pv_test_run("config.rejects_unsafe_parent", config_rejects_unsafe_parent);
    pv_test_run("config.accepts_crlf", config_accepts_crlf);
    pv_test_run(
        "config.rejects_duplicate_nul_and_size_limits",
        config_rejects_duplicate_nul_and_size_limits
    );
    pv_test_run(
        "config.parse_is_transactional_on_error",
        config_parse_is_transactional_on_error
    );
}
