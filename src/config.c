#include "pvault_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static pv_status xdg_path(char *const out, const size_t out_len, const char *const env_name, const char *const suffix)
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
    status = xdg_path(config->vault_path, sizeof(config->vault_path), "XDG_DATA_HOME", "pvault/vault.pvlt");
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

static pv_status parse_unsigned(const char *const value, const unsigned min, const unsigned max, unsigned *const out)
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

pv_status pv_config_load(pv_config *const config)
{
    char path[PATH_MAX];
    FILE *file;
    char line[PATH_MAX + 128U];
    pv_status status;

    status = pv_config_defaults(config);
    if (status != PV_OK) {
        return status;
    }
    status = xdg_path(path, sizeof(path), "XDG_CONFIG_HOME", "pvault/config");
    if (status != PV_OK) {
        return status;
    }
    file = fopen(path, "r");
    if (file == NULL) {
        return errno == ENOENT ? PV_OK : PV_ERR_IO;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char *key;
        char *value;
        char *equals;

        key = trim(line);
        if (*key == '\0' || *key == '#') {
            continue;
        }
        equals = strchr(key, '=');
        if (equals == NULL) {
            status = PV_ERR_FORMAT;
            break;
        }
        *equals = '\0';
        value = trim(equals + 1);
        key = trim(key);
        if (strcmp(key, "vault_path") == 0) {
            if (value[0] != '/' || strlen(value) >= sizeof(config->vault_path)) {
                status = PV_ERR_FORMAT;
                break;
            }
            (void)strcpy(config->vault_path, value);
        } else if (strcmp(key, "clipboard_ttl_seconds") == 0) {
            status = parse_unsigned(value, 1U, 300U, &config->clipboard_ttl);
        } else if (strcmp(key, "session_idle_seconds") == 0) {
            status = parse_unsigned(value, 30U, 86400U, &config->session_ttl);
        } else if (strcmp(key, "backup_retention") == 0) {
            status = parse_unsigned(value, 1U, 1000U, &config->backup_retention);
        } else if (strcmp(key, "picker") == 0) {
            if (strcmp(value, "internal") == 0) {
                config->picker_rofi = false;
            } else if (strcmp(value, "rofi") == 0) {
                config->picker_rofi = true;
            } else {
                status = PV_ERR_FORMAT;
            }
        } else {
            status = PV_ERR_FORMAT;
        }
        if (status != PV_OK) {
            break;
        }
    }
    if (ferror(file) != 0 && status == PV_OK) {
        status = PV_ERR_IO;
    }
    if (fclose(file) != 0 && status == PV_OK) {
        status = PV_ERR_IO;
    }
    return status;
}
