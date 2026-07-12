#include "pvault_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PV_CONFIG_MAX_BYTES (64U * 1024U)
#define PV_CONFIG_MAX_LINE (PATH_MAX + 128U)

enum pv_config_key {
    PV_CONFIG_KEY_VAULT_PATH = 1U << 0,
    PV_CONFIG_KEY_CLIPBOARD_TTL = 1U << 1,
    PV_CONFIG_KEY_SESSION_TTL = 1U << 2,
    PV_CONFIG_KEY_BACKUP_RETENTION = 1U << 3,
    PV_CONFIG_KEY_PICKER = 1U << 4
};

static pv_status xdg_path(
    char *const out,
    const size_t out_len,
    const char *const env_name,
    const char *const suffix
)
{
    const char *base = getenv(env_name);
    const char *home;
    int written;

    if (base != NULL && base[0] == '/') {
        written = snprintf(out, out_len, "%s/%s", base, suffix);
    } else {
        home = getenv("HOME");
        if (home == NULL || home[0] != '/') {
            return PV_ERR_STATE;
        }
        if (strcmp(env_name, "XDG_DATA_HOME") == 0) {
            written = snprintf(out, out_len, "%s/.local/share/%s", home, suffix);
        } else {
            written = snprintf(out, out_len, "%s/.config/%s", home, suffix);
        }
    }
    if (written < 0 || (size_t)written >= out_len) {
        return PV_ERR_LIMIT;
    }
    return PV_OK;
}

pv_status pv_config_defaults(pv_config *const config)
{
    pv_status status;

    if (config == NULL) {
        return PV_ERR_USAGE;
    }
    memset(config, 0, sizeof(*config));
    status = xdg_path(
        config->vault_path,
        sizeof(config->vault_path),
        "XDG_DATA_HOME",
        "pvault/vault.pvlt"
    );
    if (status != PV_OK) {
        return status;
    }
    config->clipboard_ttl = PV_DEFAULT_CLIPBOARD_TTL;
    config->session_ttl = PV_DEFAULT_SESSION_TTL;
    config->backup_retention = PV_DEFAULT_BACKUP_RETENTION;
    return PV_OK;
}

static bool ascii_space(const char character)
{
    return character == ' ' || character == '\t' || character == '\n' ||
        character == '\r' || character == '\f' || character == '\v';
}

static char *trim(char *text)
{
    char *end;

    while (*text != '\0' && ascii_space(*text)) {
        ++text;
    }
    if (*text == '\0') {
        return text;
    }
    end = text + strlen(text) - 1;
    while (end > text && ascii_space(*end)) {
        *end-- = '\0';
    }
    return text;
}

static pv_status parse_unsigned(
    const char *const value,
    const unsigned min,
    const unsigned max,
    unsigned *const out
)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed < min || parsed > max) {
        return PV_ERR_FORMAT;
    }
    *out = (unsigned)parsed;
    return PV_OK;
}

static pv_status validate_config_parent(const int directory_fd)
{
    struct stat info;

    if (fstat(directory_fd, &info) != 0) {
        return PV_ERR_IO;
    }
    if (!S_ISDIR(info.st_mode) || info.st_uid != geteuid() ||
        (info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return PV_ERR_IO;
    }
    return PV_OK;
}

static pv_status validate_config_file(const int fd, struct stat *const info)
{
    if (fstat(fd, info) != 0) {
        return PV_ERR_IO;
    }
    if (!S_ISREG(info->st_mode) || info->st_uid != geteuid() || info->st_nlink != 1 ||
        ((info->st_mode & 07777) != 0400 && (info->st_mode & 07777) != 0600)) {
        return PV_ERR_IO;
    }
    if (info->st_size < 0 || (uintmax_t)info->st_size > (uintmax_t)PV_CONFIG_MAX_BYTES) {
        return PV_ERR_LIMIT;
    }
    return PV_OK;
}

static pv_status open_config_file(
    const char *const path,
    int *const output_fd,
    struct stat *const output_info,
    bool *const present
)
{
    char directory[PATH_MAX];
    const char *name;
    const char *slash;
    size_t directory_len;
    int directory_fd = -1;
    int fd = -1;
    pv_status status;

    if (path == NULL || output_fd == NULL || output_info == NULL || present == NULL) {
        return PV_ERR_USAGE;
    }
    *output_fd = -1;
    *present = false;
    slash = strrchr(path, '/');
    if (slash == NULL || slash[1] == '\0') {
        return PV_ERR_STATE;
    }
    directory_len = (size_t)(slash - path);
    if (directory_len == 0U) {
        directory_len = 1U;
    }
    if (directory_len >= sizeof(directory)) {
        return PV_ERR_LIMIT;
    }
    memcpy(directory, path, directory_len);
    directory[directory_len] = '\0';
    name = slash + 1;

    directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd < 0) {
        return errno == ENOENT ? PV_OK : PV_ERR_IO;
    }
    status = validate_config_parent(directory_fd);
    if (status != PV_OK) {
        (void)close(directory_fd);
        return status;
    }
    fd = openat(directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        const int saved_errno = errno;

        (void)close(directory_fd);
        return saved_errno == ENOENT ? PV_OK : PV_ERR_IO;
    }
    status = validate_config_file(fd, output_info);
    if (close(directory_fd) != 0 && status == PV_OK) {
        status = PV_ERR_IO;
    }
    if (status != PV_OK) {
        (void)close(fd);
        return status;
    }
    *output_fd = fd;
    *present = true;
    return PV_OK;
}

static pv_status read_config_file(
    const int fd,
    const struct stat *const initial_info,
    char **const output,
    size_t *const output_len
)
{
    char *content;
    size_t used = 0U;
    pv_status status = PV_OK;
    struct stat final_info;

    if (fd < 0 || initial_info == NULL || output == NULL || output_len == NULL) {
        return PV_ERR_USAGE;
    }
    *output = NULL;
    *output_len = 0U;
    content = malloc(PV_CONFIG_MAX_BYTES + 1U);
    if (content == NULL) {
        return PV_ERR_NOMEM;
    }
    while (used < PV_CONFIG_MAX_BYTES) {
        ssize_t received = read(fd, content + used, PV_CONFIG_MAX_BYTES - used);

        if (received > 0) {
            used += (size_t)received;
            continue;
        }
        if (received == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        status = PV_ERR_IO;
        break;
    }
    if (status == PV_OK && used == PV_CONFIG_MAX_BYTES) {
        char extra;
        ssize_t received;

        do {
            received = read(fd, &extra, 1U);
        } while (received < 0 && errno == EINTR);
        if (received > 0) {
            status = PV_ERR_LIMIT;
        } else if (received < 0) {
            status = PV_ERR_IO;
        }
    }
    if (status == PV_OK && fstat(fd, &final_info) != 0) {
        status = PV_ERR_IO;
    }
    if (status == PV_OK &&
        (final_info.st_dev != initial_info->st_dev ||
            final_info.st_ino != initial_info->st_ino ||
            final_info.st_uid != initial_info->st_uid ||
            final_info.st_nlink != initial_info->st_nlink ||
            (final_info.st_mode & 07777) != (initial_info->st_mode & 07777) ||
            final_info.st_size < 0 || final_info.st_size != initial_info->st_size ||
            (uintmax_t)final_info.st_size != (uintmax_t)used ||
            final_info.st_mtim.tv_sec != initial_info->st_mtim.tv_sec ||
            final_info.st_mtim.tv_nsec != initial_info->st_mtim.tv_nsec ||
            final_info.st_ctim.tv_sec != initial_info->st_ctim.tv_sec ||
            final_info.st_ctim.tv_nsec != initial_info->st_ctim.tv_nsec)) {
        status = PV_ERR_IO;
    }
    if (status == PV_OK && memchr(content, '\0', used) != NULL) {
        status = PV_ERR_FORMAT;
    }
    if (status != PV_OK) {
        free(content);
        return status;
    }
    content[used] = '\0';
    *output = content;
    *output_len = used;
    return PV_OK;
}

static pv_status mark_key(unsigned *const seen, const unsigned key)
{
    if ((*seen & key) != 0U) {
        return PV_ERR_FORMAT;
    }
    *seen |= key;
    return PV_OK;
}

static pv_status parse_config_line(
    pv_config *const config,
    char *const line,
    unsigned *const seen
)
{
    char *key;
    char *value;
    char *equals;
    pv_status status;

    key = trim(line);
    if (*key == '\0' || *key == '#') {
        return PV_OK;
    }
    equals = strchr(key, '=');
    if (equals == NULL) {
        return PV_ERR_FORMAT;
    }
    *equals = '\0';
    value = trim(equals + 1);
    key = trim(key);
    if (strcmp(key, "vault_path") == 0) {
        status = mark_key(seen, PV_CONFIG_KEY_VAULT_PATH);
        if (status != PV_OK || value[0] != '/' || strlen(value) >= sizeof(config->vault_path)) {
            return PV_ERR_FORMAT;
        }
        memcpy(config->vault_path, value, strlen(value) + 1U);
        return PV_OK;
    }
    if (strcmp(key, "clipboard_ttl_seconds") == 0) {
        status = mark_key(seen, PV_CONFIG_KEY_CLIPBOARD_TTL);
        return status == PV_OK
            ? parse_unsigned(value, 1U, 300U, &config->clipboard_ttl)
            : status;
    }
    if (strcmp(key, "session_idle_seconds") == 0) {
        status = mark_key(seen, PV_CONFIG_KEY_SESSION_TTL);
        return status == PV_OK
            ? parse_unsigned(value, 30U, 86400U, &config->session_ttl)
            : status;
    }
    if (strcmp(key, "backup_retention") == 0) {
        status = mark_key(seen, PV_CONFIG_KEY_BACKUP_RETENTION);
        return status == PV_OK
            ? parse_unsigned(value, 1U, 1000U, &config->backup_retention)
            : status;
    }
    if (strcmp(key, "picker") == 0) {
        status = mark_key(seen, PV_CONFIG_KEY_PICKER);
        if (status != PV_OK) {
            return status;
        }
        if (strcmp(value, "internal") == 0) {
            config->picker_rofi = false;
            return PV_OK;
        }
        if (strcmp(value, "rofi") == 0) {
            config->picker_rofi = true;
            return PV_OK;
        }
    }
    return PV_ERR_FORMAT;
}

static pv_status parse_config(
    pv_config *const config,
    char *const content,
    const size_t content_len
)
{
    char *cursor = content;
    char *const end = content + content_len;
    unsigned seen = 0U;

    while (cursor < end) {
        char *const newline = memchr(cursor, '\n', (size_t)(end - cursor));
        char *const line_end = newline != NULL ? newline : end;
        const size_t line_len = (size_t)(line_end - cursor);
        pv_status status;

        if (line_len > PV_CONFIG_MAX_LINE) {
            return PV_ERR_LIMIT;
        }
        *line_end = '\0';
        status = parse_config_line(config, cursor, &seen);
        if (status != PV_OK) {
            return status;
        }
        cursor = newline != NULL ? newline + 1 : end;
    }
    return PV_OK;
}

pv_status pv_config_load(pv_config *const config)
{
    pv_config candidate;
    char path[PATH_MAX];
    char *content = NULL;
    size_t content_len = 0U;
    struct stat initial_info;
    bool present = false;
    int fd = -1;
    pv_status status;

    if (config == NULL) {
        return PV_ERR_USAGE;
    }
    status = pv_config_defaults(&candidate);
    if (status == PV_OK) {
        status = xdg_path(path, sizeof(path), "XDG_CONFIG_HOME", "pvault/config");
    }
    if (status == PV_OK) {
        status = open_config_file(path, &fd, &initial_info, &present);
    }
    if (status == PV_OK && present) {
        status = read_config_file(fd, &initial_info, &content, &content_len);
    }
    if (fd >= 0 && close(fd) != 0 && status == PV_OK) {
        status = PV_ERR_IO;
    }
    if (status == PV_OK && present) {
        status = parse_config(&candidate, content, content_len);
    }
    free(content);
    if (status == PV_OK) {
        *config = candidate;
    }
    sodium_memzero(&candidate, sizeof(candidate));
    return status;
}
