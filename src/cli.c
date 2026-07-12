#include "cli.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct record_form {
    pv_buffer title;
    pv_buffer username;
    pv_buffer password;
    pv_buffer urls_text;
    pv_buffer notes;
    pv_buffer tags_text;
    pv_slice urls[PV_MAX_COLLECTION_ITEMS];
    pv_slice tags[PV_MAX_COLLECTION_ITEMS];
    pv_custom_field fields[PV_MAX_COLLECTION_ITEMS];
    pv_buffer field_names[PV_MAX_COLLECTION_ITEMS];
    pv_buffer field_values[PV_MAX_COLLECTION_ITEMS];
    size_t url_count;
    size_t tag_count;
    size_t field_count;
} record_form;

typedef struct rofi_job {
    int input_fd;
    int output_fd;
    pid_t pid;
} rofi_job;

static bool status_committed(const pv_status status)
{
    return status == PV_OK || status == PV_ERR_DURABILITY;
}

static pv_status validate_new_master_password(const pv_buffer *const password)
{
    if (password != NULL &&
        pv_master_password_is_acceptable(password->data, password->len)) {
        return PV_OK;
    }
    (void)fprintf(
        stderr,
        "pvault: master password must be at least 16 bytes and not a common value, "
        "full sequence, or periodic repetition; prefer a randomly generated 5-6 word passphrase\n"
    );
    return PV_ERR_USAGE;
}

static pv_status read_exact(const int fd, void *const output, const size_t length)
{
    uint8_t *cursor = output;
    size_t remaining = length;

    while (remaining > 0U) {
        const ssize_t received = read(fd, cursor, remaining);

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return PV_ERR_IO;
        }
        cursor += (size_t)received;
        remaining -= (size_t)received;
    }
    return PV_OK;
}

static bool socket_write_all(const int fd, const void *const input, const size_t length)
{
    const uint8_t *cursor = input;
    size_t remaining = length;

    while (remaining > 0U) {
        const ssize_t written = send(fd, cursor, remaining, MSG_NOSIGNAL);

        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        cursor += (size_t)written;
        remaining -= (size_t)written;
    }
    return true;
}

static bool socket_write_title(const int fd, const pv_slice *const title)
{
    static const char replacement = '?';
    size_t position = 0U;
    size_t safe_start = 0U;

    while (position < title->len) {
        const uint8_t byte = title->data[position];

        if (byte < 0x20U || byte == 0x7fU) {
            if (!socket_write_all(fd, title->data + safe_start, position - safe_start) ||
                !socket_write_all(fd, &replacement, 1U)) {
                return false;
            }
            ++position;
            safe_start = position;
        } else {
            ++position;
        }
    }
    return socket_write_all(fd, title->data + safe_start, position - safe_start);
}

static void print_usage(FILE *const stream)
{
    (void)fprintf(
        stream,
        "Usage: pvault [--vault PATH] COMMAND [OPTIONS]\n"
        "Commands:\n"
        "  init --recovery-out PATH   Create a new vault\n"
        "  add                         Add a credential\n"
        "  edit QUERY                  Edit a credential\n"
        "  remove QUERY                Delete a credential\n"
        "  list [QUERY]                List credentials\n"
        "  show QUERY                  Show non-secret fields\n"
        "  copy QUERY [--field NAME]   Copy a field for the configured TTL\n"
        "  pick [--copy] [--rofi]      Keyboard-driven picker\n"
        "  generate [--length N]       Generate and copy a password\n"
        "  passwd [--recovery FILE]    Change the master password\n"
        "  recovery rotate --out PATH Rotate the recovery key\n"
        "  backup --output PATH        Create an encrypted backup\n"
        "  restore BACKUP              Authenticate and restore a backup\n"
        "  rescue inspect SNAPSHOT     Inspect unauthenticated metadata\n"
        "  rescue verify SNAPSHOT      Authenticate a snapshot read-only\n"
        "  rescue recover SNAPSHOT --output PATH\n"
        "                              Create an authenticated recovery copy\n"
        "  rollback SNAPSHOT --output PATH\n"
        "                              Create a separate rollback copy\n"
        "  config check                Validate configuration and permissions\n"
        "  doctor                      Validate structure and authentication\n"
        "  shell                       Open a five-minute session\n"
    );
}

static bool print_command_usage(
    FILE *const stream,
    const char *const command,
    const char *const topic
)
{
    const char *usage = NULL;

    if (strcmp(command, "init") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] init --recovery-out PATH\n";
    } else if (strcmp(command, "add") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] add\n";
    } else if (strcmp(command, "edit") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] edit QUERY\n";
    } else if (strcmp(command, "remove") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] remove QUERY\n";
    } else if (strcmp(command, "list") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] list [QUERY]\n";
    } else if (strcmp(command, "show") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] show QUERY\n";
    } else if (strcmp(command, "copy") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] copy QUERY [--field NAME] [--ttl SECONDS]\n";
    } else if (strcmp(command, "pick") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] pick [--copy] [--rofi]\n";
    } else if (strcmp(command, "generate") == 0 && topic == NULL) {
        usage = "Usage: pvault generate [--length N]\n";
    } else if (strcmp(command, "passwd") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] passwd [--recovery FILE]\n";
    } else if (strcmp(command, "recovery") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] recovery rotate --out PATH\n";
    } else if (strcmp(command, "recovery") == 0 && topic != NULL &&
        strcmp(topic, "rotate") == 0) {
        usage = "Usage: pvault [--vault PATH] recovery rotate --out PATH\n";
    } else if (strcmp(command, "backup") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] backup --output PATH\n";
    } else if (strcmp(command, "restore") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] restore BACKUP\n";
    } else if (strcmp(command, "doctor") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] doctor\n";
    } else if (strcmp(command, "shell") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] shell\n";
    } else if (strcmp(command, "rescue") == 0 && topic == NULL) {
        usage =
            "Usage: pvault rescue inspect SNAPSHOT\n"
            "       pvault rescue verify SNAPSHOT [--recovery FILE]\n"
            "       pvault rescue recover SNAPSHOT --output PATH [--recovery FILE]\n";
    } else if (strcmp(command, "rescue") == 0 && topic != NULL &&
        strcmp(topic, "inspect") == 0) {
        usage = "Usage: pvault rescue inspect SNAPSHOT\n";
    } else if (strcmp(command, "rescue") == 0 && topic != NULL &&
        strcmp(topic, "verify") == 0) {
        usage = "Usage: pvault rescue verify SNAPSHOT [--recovery FILE]\n";
    } else if (strcmp(command, "rescue") == 0 && topic != NULL &&
        strcmp(topic, "recover") == 0) {
        usage = "Usage: pvault rescue recover SNAPSHOT --output PATH [--recovery FILE]\n";
    } else if (strcmp(command, "rollback") == 0 && topic == NULL) {
        usage = "Usage: pvault rollback SNAPSHOT --output PATH [--recovery FILE]\n";
    } else if (strcmp(command, "config") == 0 && topic == NULL) {
        usage = "Usage: pvault config check\n";
    }
    if (usage == NULL) {
        return false;
    }
    (void)fputs(usage, stream);
    return true;
}

static pv_status open_password_vault(
    const pv_cli_context *const context,
    pv_vault *const vault,
    pv_file_header *const header
)
{
    pv_buffer password = { 0 };
    pv_status status;

    status = pv_secure_read_secret("Master password: ", &password, false);
    if (status == PV_OK) {
        status = pv_store_open_password_consume(
            context->config.vault_path,
            &password,
            vault,
            header
        );
    }
    pv_buffer_secure_free(&password);
    return status;
}

static bool record_matches_query(const pv_record *const record, const char *const query)
{
    size_t i;

    if (query == NULL || query[0] == '\0') return true;
    if (pv_slice_contains_cstr(&record->title, query, true) ||
        pv_slice_contains_cstr(&record->username, query, true)) return true;
    for (i = 0U; i < record->url_count; ++i) {
        if (pv_slice_contains_cstr(&record->urls[i], query, true)) return true;
    }
    for (i = 0U; i < record->tag_count; ++i) {
        if (pv_slice_contains_cstr(&record->tags[i], query, true)) return true;
    }
    return false;
}

static void print_slice(const pv_slice *const slice)
{
    pv_text_fprint(stdout, slice);
}

static void print_record_line(const pv_record *const record)
{
    char id[PV_RECORD_ID_BYTES * 2U + 1U];

    pv_hex_encode(record->id, PV_RECORD_ID_BYTES, id, sizeof(id));
    (void)printf("%.8s  %c ", id, (record->flags & PV_RECORD_FAVORITE) != 0U ? '*' : ' ');
    print_slice(&record->title);
    if (record->username.len > 0U) {
        (void)printf("  [");
        print_slice(&record->username);
        (void)printf("]");
    }
    (void)printf("\n");
}

static pv_record *find_unique(pv_vault *const vault, const char *const query, pv_status *const status)
{
    size_t matches = 0U;
    pv_record *record;

    record = pv_model_find(vault, query, &matches);
    if (record == NULL || matches == 0U) {
        *status = PV_ERR_NOT_FOUND;
        return NULL;
    }
    if (matches != 1U) {
        (void)fprintf(stderr, "pvault: query matched %zu records; use the full record ID\n", matches);
        *status = PV_ERR_USAGE;
        return NULL;
    }
    *status = PV_OK;
    return record;
}

static pv_status generate_password(const unsigned length, pv_buffer *const password)
{
    static const char lower[] = "abcdefghijkmnopqrstuvwxyz";
    static const char upper[] = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    static const char digits[] = "23456789";
    static const char symbols[] = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
    static const char all[] =
        "abcdefghijkmnopqrstuvwxyz"
        "ABCDEFGHJKLMNPQRSTUVWXYZ"
        "23456789"
        "!#$%&()*+,-./:;<=>?@[]^_{|}~";
    unsigned i;

    if (password == NULL || length < 12U || length > 256U) {
        return PV_ERR_USAGE;
    }
    *password = (pv_buffer){ .secure = true };
    password->data = sodium_malloc((size_t)length + 1U);
    if (password->data == NULL || sodium_mlock(password->data, (size_t)length + 1U) != 0) {
        sodium_free(password->data);
        password->data = NULL;
        return PV_ERR_SECURE_MEMORY;
    }
    password->data[0] = (uint8_t)lower[randombytes_uniform((uint32_t)(sizeof(lower) - 1U))];
    password->data[1] = (uint8_t)upper[randombytes_uniform((uint32_t)(sizeof(upper) - 1U))];
    password->data[2] = (uint8_t)digits[randombytes_uniform((uint32_t)(sizeof(digits) - 1U))];
    password->data[3] = (uint8_t)symbols[randombytes_uniform((uint32_t)(sizeof(symbols) - 1U))];
    for (i = 4U; i < length; ++i) {
        password->data[i] = (uint8_t)all[randombytes_uniform((uint32_t)(sizeof(all) - 1U))];
    }
    for (i = length - 1U; i > 0U; --i) {
        const unsigned j = randombytes_uniform(i + 1U);
        const uint8_t temporary = password->data[i];
        password->data[i] = password->data[j];
        password->data[j] = temporary;
    }
    password->data[length] = 0U;
    password->len = length;
    return PV_OK;
}

static void record_form_destroy(record_form *const form)
{
    size_t i;

    if (form == NULL) {
        return;
    }
    pv_buffer_secure_free(&form->title);
    pv_buffer_secure_free(&form->username);
    pv_buffer_secure_free(&form->password);
    pv_buffer_secure_free(&form->urls_text);
    pv_buffer_secure_free(&form->notes);
    pv_buffer_secure_free(&form->tags_text);
    for (i = 0U; i < form->field_count; ++i) {
        pv_buffer_secure_free(&form->field_names[i]);
        pv_buffer_secure_free(&form->field_values[i]);
    }
    sodium_memzero(form, sizeof(*form));
}

static pv_status split_csv(pv_buffer *const source, pv_slice *const items, size_t *const count, const size_t max_len)
{
    uint8_t *cursor;
    uint8_t *end;

    *count = 0U;
    if (source->len == 0U) {
        return PV_OK;
    }
    cursor = source->data;
    end = source->data + source->len;
    while (cursor < end) {
        uint8_t *start;
        uint8_t *finish;
        while (cursor < end && (*cursor == (uint8_t)' ' || *cursor == (uint8_t)'\t' || *cursor == (uint8_t)',')) {
            ++cursor;
        }
        start = cursor;
        while (cursor < end && *cursor != (uint8_t)',') {
            ++cursor;
        }
        finish = cursor;
        while (finish > start && (finish[-1] == (uint8_t)' ' || finish[-1] == (uint8_t)'\t')) {
            --finish;
        }
        if (finish > start) {
            if (*count >= PV_MAX_COLLECTION_ITEMS || (size_t)(finish - start) > max_len) {
                return PV_ERR_LIMIT;
            }
            items[*count] = (pv_slice){ .data = start, .len = (size_t)(finish - start) };
            ++*count;
        }
        if (cursor < end) {
            *cursor++ = 0U;
        }
    }
    return PV_OK;
}

static pv_status collect_custom_fields(record_form *const form)
{
    unsigned count;
    unsigned i;
    pv_status status;

    status = pv_tty_read_unsigned("Custom fields count [0]: ", PV_MAX_COLLECTION_ITEMS, 0U, &count);
    if (status != PV_OK) {
        return status;
    }
    form->field_count = count;
    for (i = 0U; i < count; ++i) {
        char prompt[64];
        bool secret;

        (void)snprintf(prompt, sizeof(prompt), "Custom field %u name: ", i + 1U);
        status = pv_tty_read_line(prompt, PV_MAX_FIELD_NAME, false, &form->field_names[i]);
        if (status != PV_OK) {
            return status;
        }
        status = pv_tty_confirm("Secret value? [y/N]: ", &secret);
        if (status != PV_OK) {
            return status;
        }
        (void)snprintf(prompt, sizeof(prompt), "Custom field %u value: ", i + 1U);
        status = secret
            ? pv_secure_read_secret(prompt, &form->field_values[i], false)
            : pv_tty_read_line(prompt, PV_MAX_FIELD_VALUE, true, &form->field_values[i]);
        if (status != PV_OK) {
            return status;
        }
        form->fields[i].name = (pv_slice){
            .data = form->field_names[i].data,
            .len = form->field_names[i].len
        };
        form->fields[i].value = (pv_slice){
            .data = form->field_values[i].data,
            .len = form->field_values[i].len
        };
        form->fields[i].flags = secret ? PV_FIELD_SECRET : 0U;
    }
    return PV_OK;
}

static pv_status collect_record(record_form *const form, pv_record *const source)
{
    pv_buffer mode = { 0 };
    pv_status status;

    memset(form, 0, sizeof(*form));
    memset(source, 0, sizeof(*source));
    status = pv_tty_read_line("Title: ", PV_MAX_TITLE, false, &form->title);
    if (status == PV_OK) {
        status = pv_tty_read_line("Username: ", PV_MAX_USERNAME, true, &form->username);
    }
    if (status == PV_OK) {
        status = pv_tty_read_line("Password [g=generate/e=enter] (g): ", 8U, true, &mode);
    }
    if (status == PV_OK && (mode.len == 0U || mode.data[0] == (uint8_t)'g' || mode.data[0] == (uint8_t)'G')) {
        status = generate_password(24U, &form->password);
    } else if (status == PV_OK) {
        status = pv_secure_read_secret("Password: ", &form->password, false);
    }
    pv_buffer_secure_free(&mode);
    if (status == PV_OK) {
        status = pv_tty_read_line("URLs (comma-separated): ", PV_MAX_URL * 4U, true, &form->urls_text);
    }
    if (status == PV_OK) {
        status = split_csv(&form->urls_text, form->urls, &form->url_count, PV_MAX_URL);
    }
    if (status == PV_OK) {
        status = pv_tty_read_line("Notes (single line): ", PV_MAX_NOTES, true, &form->notes);
    }
    if (status == PV_OK) {
        status = pv_tty_read_line("Tags (comma-separated): ", PV_MAX_TAG * 8U, true, &form->tags_text);
    }
    if (status == PV_OK) {
        status = split_csv(&form->tags_text, form->tags, &form->tag_count, PV_MAX_TAG);
    }
    if (status == PV_OK) {
        status = collect_custom_fields(form);
    }
    if (status != PV_OK) {
        record_form_destroy(form);
        return status;
    }
    source->title = (pv_slice){ form->title.data, form->title.len };
    source->username = (pv_slice){ form->username.data, form->username.len };
    source->password = (pv_slice){ form->password.data, form->password.len };
    source->urls = form->urls;
    source->url_count = form->url_count;
    source->notes = (pv_slice){ form->notes.data, form->notes.len };
    source->tags = form->tags;
    source->tag_count = form->tag_count;
    source->fields = form->fields;
    source->field_count = form->field_count;
    return PV_OK;
}

static pv_status command_init(pv_cli_context *const context, const int argc, char **const argv)
{
    const char *recovery_out = NULL;
    pv_buffer password = { 0 };
    pv_buffer recovery_key = { 0 };
    pv_buffer recovery_text = { 0 };
    pv_vault vault = { 0 };
    pv_status status;
    pv_status commit_status = PV_OK;
    int i;

    for (i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--recovery-out") == 0 && i + 1 < argc) {
            recovery_out = argv[++i];
        } else if (strcmp(argv[i], "--vault") == 0 && i + 1 < argc) {
            const char *const vault_path = argv[++i];
            const size_t vault_path_len = strlen(vault_path);

            if (vault_path_len >= sizeof(context->config.vault_path) || vault_path[0] != '/') {
                return PV_ERR_USAGE;
            }
            (void)memcpy(context->config.vault_path, vault_path, vault_path_len + 1U);
        } else {
            return PV_ERR_USAGE;
        }
    }
    if (recovery_out == NULL) {
        (void)fprintf(stderr, "pvault: init requires --recovery-out PATH\n");
        return PV_ERR_USAGE;
    }
    status = pv_secure_buffer_alloc(&recovery_key, PV_RECOVERY_KEY_BYTES);
    if (status == PV_OK) {
        status = pv_secure_buffer_alloc(&recovery_text, PV_RECOVERY_TEXT_MAX);
    }
    if (status == PV_OK) {
        status = pv_secure_read_secret("New master password: ", &password, true);
    }
    if (status == PV_OK) {
        status = validate_new_master_password(&password);
    }
    if (status == PV_OK) {
        randombytes_buf(recovery_key.data, recovery_key.len);
        status = pv_store_create_consume(
            context->config.vault_path,
            &password,
            recovery_key.data,
            &vault
        );
        if (status == PV_ERR_DURABILITY) {
            commit_status = status;
            status = PV_OK;
        }
    }
    pv_buffer_secure_free(&password);
    if (status == PV_OK) {
        status = pv_recovery_encode(
            vault.vault_id,
            recovery_key.data,
            (char *)recovery_text.data,
            recovery_text.len
        );
    }
    if (status == PV_OK) {
        status = pv_recovery_write_file(recovery_out, (const char *)recovery_text.data, vault.vault_id);
        if (status != PV_OK) {
            (void)fprintf(
                stderr,
                "pvault: vault creation committed, but the recovery file was not created\n"
                "pvault: keep the master password and run 'pvault recovery rotate --out PATH'\n"
            );
        }
    }
    if (status == PV_OK) {
        (void)printf(
            "Vault created at the requested vault path.\n"
            "Recovery key written to the requested recovery output path.\n"
        );
        status = commit_status;
    }
    pv_model_destroy(&vault);
    pv_buffer_secure_free(&recovery_key);
    pv_buffer_secure_free(&recovery_text);
    return status;
}

static pv_status command_add(pv_cli_context *const context)
{
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    record_form form = { 0 };
    pv_record source = { 0 };
    pv_record *created = NULL;
    pv_status status;

    status = open_password_vault(context, &vault, &header);
    if (status == PV_OK) {
        status = collect_record(&form, &source);
    }
    if (status == PV_OK) {
        status = pv_model_add_record(&vault, &source, &created);
    }
    if (status == PV_OK) {
        status = pv_store_save(&vault, &header, context->config.backup_retention);
    }
    if (status_committed(status) && created != NULL) {
        char id[PV_RECORD_ID_BYTES * 2U + 1U];
        pv_hex_encode(created->id, PV_RECORD_ID_BYTES, id, sizeof(id));
        (void)printf("Added %.8s\n", id);
    }
    if (vault.arena.base != NULL) {
        pv_model_destroy(&vault);
    }
    record_form_destroy(&form);
    sodium_memzero(&source, sizeof(source));
    sodium_memzero(&header, sizeof(header));
    return status;
}

static pv_status replace_slice(
    pv_vault *const vault,
    pv_slice *const destination,
    const pv_buffer *const value,
    const size_t maximum
)
{
    pv_slice replacement;
    pv_status status;

    status = pv_arena_copy(&vault->arena, &replacement, value->data, value->len, maximum);
    if (status == PV_OK) {
        if (destination->data != NULL) {
            sodium_memzero(destination->data, destination->len);
        }
        *destination = replacement;
    }
    return status;
}

static pv_status command_edit(pv_cli_context *const context, const char *const query)
{
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    pv_record *record;
    pv_buffer field = { 0 };
    pv_buffer value = { 0 };
    pv_status status;

    status = open_password_vault(context, &vault, &header);
    if (status != PV_OK) {
        return status;
    }
    record = find_unique(&vault, query, &status);
    if (status == PV_OK && record->revision == UINT64_MAX) {
        status = PV_ERR_LIMIT;
    }
    if (status == PV_OK) {
        status = pv_tty_read_line(
            "Field [title/username/password/urls/notes/tags/favorite]: ",
            32U,
            false,
            &field
        );
    }
    if (status == PV_OK) {
        status = pv_arena_set_readwrite(&vault.arena);
    }
    if (status == PV_OK && strcmp((const char *)field.data, "favorite") == 0) {
        record->flags ^= PV_RECORD_FAVORITE;
    } else if (status == PV_OK && strcmp((const char *)field.data, "password") == 0) {
        status = pv_secure_read_secret("New password: ", &value, false);
        if (status == PV_OK) {
            status = replace_slice(&vault, &record->password, &value, PV_MAX_PASSWORD);
        }
    } else if (status == PV_OK && strcmp((const char *)field.data, "title") == 0) {
        status = pv_tty_read_line("New title: ", PV_MAX_TITLE, false, &value);
        if (status == PV_OK) {
            status = replace_slice(&vault, &record->title, &value, PV_MAX_TITLE);
        }
    } else if (status == PV_OK && strcmp((const char *)field.data, "username") == 0) {
        status = pv_tty_read_line("New username: ", PV_MAX_USERNAME, true, &value);
        if (status == PV_OK) {
            status = replace_slice(&vault, &record->username, &value, PV_MAX_USERNAME);
        }
    } else if (status == PV_OK && strcmp((const char *)field.data, "notes") == 0) {
        status = pv_tty_read_line("New notes: ", PV_MAX_NOTES, true, &value);
        if (status == PV_OK) {
            status = replace_slice(&vault, &record->notes, &value, PV_MAX_NOTES);
        }
    } else if (status == PV_OK &&
               (strcmp((const char *)field.data, "urls") == 0 || strcmp((const char *)field.data, "tags") == 0)) {
        pv_slice parsed[PV_MAX_COLLECTION_ITEMS];
        size_t count = 0U;
        const bool urls = field.data[0] == (uint8_t)'u';
        status = pv_tty_read_line(urls ? "New URLs: " : "New tags: ", urls ? PV_MAX_URL * 4U : PV_MAX_TAG * 8U, true, &value);
        if (status == PV_OK) {
            status = split_csv(&value, parsed, &count, urls ? PV_MAX_URL : PV_MAX_TAG);
        }
        if (status == PV_OK) {
            size_t i;
            pv_slice *copies = NULL;
            if (count > 0U) {
                copies = pv_arena_alloc(&vault.arena, count * sizeof(*copies), _Alignof(pv_slice));
                if (copies == NULL) {
                    status = PV_ERR_LIMIT;
                }
            }
            for (i = 0U; status == PV_OK && i < count; ++i) {
                status = pv_arena_copy(&vault.arena, &copies[i], parsed[i].data, parsed[i].len, urls ? PV_MAX_URL : PV_MAX_TAG);
            }
            if (status == PV_OK && urls) {
                for (i = 0U; i < record->url_count; ++i) {
                    sodium_memzero(record->urls[i].data, record->urls[i].len);
                }
                record->urls = copies;
                record->url_count = count;
            } else if (status == PV_OK) {
                for (i = 0U; i < record->tag_count; ++i) {
                    sodium_memzero(record->tags[i].data, record->tags[i].len);
                }
                record->tags = copies;
                record->tag_count = count;
            }
        }
        sodium_memzero(parsed, sizeof(parsed));
    } else if (status == PV_OK) {
        status = PV_ERR_USAGE;
    }
    if (status == PV_OK) {
        ++record->revision;
        record->updated_ms = pv_now_ms();
        vault.updated_ms = record->updated_ms;
        vault.dirty = true;
        status = pv_store_save(&vault, &header, context->config.backup_retention);
    }
    if (status_committed(status) && record != NULL) {
        char id[PV_RECORD_ID_BYTES * 2U + 1U];

        pv_hex_encode(record->id, PV_RECORD_ID_BYTES, id, sizeof(id));
        (void)printf("Updated %.8s\n", id);
    }
    pv_buffer_secure_free(&field);
    pv_buffer_secure_free(&value);
    pv_model_destroy(&vault);
    sodium_memzero(&header, sizeof(header));
    return status;
}

static pv_status command_remove(pv_cli_context *const context, const char *const query)
{
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    pv_record *record;
    bool confirmed = false;
    bool cancelled = false;
    pv_status status;

    status = open_password_vault(context, &vault, &header);
    if (status == PV_OK) {
        record = find_unique(&vault, query, &status);
    } else {
        record = NULL;
    }
    if (status == PV_OK) {
        (void)printf("Delete '");
        print_slice(&record->title);
        (void)printf("'?\n");
        status = pv_tty_confirm("Confirm [y/N]: ", &confirmed);
    }
    if (status == PV_OK && !confirmed) {
        cancelled = true;
        (void)printf("Deletion cancelled\n");
    }
    if (status == PV_OK && !cancelled) {
        status = pv_model_delete(&vault, record);
    }
    if (status == PV_OK && !cancelled) {
        status = pv_store_save(&vault, &header, context->config.backup_retention);
    }
    if (!cancelled && status_committed(status)) {
        (void)printf("Record removed\n");
    }
    if (vault.arena.base != NULL) {
        pv_model_destroy(&vault);
    }
    sodium_memzero(&header, sizeof(header));
    return status;
}

static pv_status command_list(pv_cli_context *const context, const char *const query)
{
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    size_t i;
    size_t shown = 0U;
    pv_status status;

    status = open_password_vault(context, &vault, &header);
    if (status != PV_OK) {
        return status;
    }
    for (i = 0U; i < vault.record_count; ++i) {
        pv_record *const record = &vault.records[i];
        if ((record->flags & PV_RECORD_DELETED) != 0U || !record_matches_query(record, query)) {
            continue;
        }
        print_record_line(record);
        ++shown;
    }
    (void)printf("%zu record%s\n", shown, shown == 1U ? "" : "s");
    pv_model_destroy(&vault);
    sodium_memzero(&header, sizeof(header));
    return PV_OK;
}

static void show_record(const pv_record *const record)
{
    size_t i;
    char id[PV_RECORD_ID_BYTES * 2U + 1U];

    pv_hex_encode(record->id, PV_RECORD_ID_BYTES, id, sizeof(id));
    (void)printf("ID: %s\nTitle: ", id);
    print_slice(&record->title);
    (void)printf("\nUsername: ");
    print_slice(&record->username);
    (void)printf("\nPassword: <secret>\nURLs:\n");
    for (i = 0U; i < record->url_count; ++i) {
        (void)printf("  - ");
        print_slice(&record->urls[i]);
        (void)printf("\n");
    }
    (void)printf("Notes: ");
    print_slice(&record->notes);
    (void)printf("\nTags: ");
    for (i = 0U; i < record->tag_count; ++i) {
        if (i > 0U) {
            (void)printf(", ");
        }
        print_slice(&record->tags[i]);
    }
    (void)printf("\nCustom fields:\n");
    for (i = 0U; i < record->field_count; ++i) {
        (void)printf("  ");
        print_slice(&record->fields[i].name);
        (void)printf(": ");
        if ((record->fields[i].flags & PV_FIELD_SECRET) != 0U) {
            (void)printf("<secret>");
        } else {
            print_slice(&record->fields[i].value);
        }
        (void)printf("\n");
    }
}

static pv_status command_show(pv_cli_context *const context, const char *const query)
{
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    pv_status status;
    pv_record *record;

    status = open_password_vault(context, &vault, &header);
    if (status == PV_OK) {
        record = find_unique(&vault, query, &status);
    } else {
        record = NULL;
    }
    if (status == PV_OK) {
        show_record(record);
    }
    if (vault.arena.base != NULL) {
        pv_model_destroy(&vault);
    }
    sodium_memzero(&header, sizeof(header));
    return status;
}

static pv_status record_field_view(const pv_record *const record, const char *const field, pv_view *const view)
{
    size_t i;

    if (strcmp(field, "password") == 0) {
        *view = (pv_view){ record->password.data, record->password.len };
    } else if (strcmp(field, "username") == 0) {
        *view = (pv_view){ record->username.data, record->username.len };
    } else if (strcmp(field, "url") == 0 && record->url_count > 0U) {
        *view = (pv_view){ record->urls[0].data, record->urls[0].len };
    } else {
        for (i = 0U; i < record->field_count; ++i) {
            if (pv_slice_equal_cstr(&record->fields[i].name, field, false)) {
                *view = (pv_view){ record->fields[i].value.data, record->fields[i].value.len };
                return view->len == 0U ? PV_ERR_NOT_FOUND : PV_OK;
            }
        }
        return PV_ERR_NOT_FOUND;
    }
    return view->len == 0U ? PV_ERR_NOT_FOUND : PV_OK;
}

static pv_status command_copy(
    pv_cli_context *const context,
    const char *const query,
    const char *const field,
    const unsigned ttl
)
{
    pv_clipboard_job job;
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    pv_record *record;
    pv_view view;
    pv_status status;

    status = pv_clipboard_prepare(&job, ttl);
    if (status != PV_OK) {
        return status;
    }
    status = open_password_vault(context, &vault, &header);
    if (status == PV_OK) {
        record = find_unique(&vault, query, &status);
    } else {
        record = NULL;
    }
    if (status == PV_OK) {
        status = record_field_view(record, field, &view);
    }
    if (status == PV_OK) {
        status = pv_clipboard_send(&job, view.data, view.len);
    } else {
        pv_clipboard_cancel(&job);
    }
    if (vault.arena.base != NULL) {
        pv_model_destroy(&vault);
    }
    sodium_memzero(&header, sizeof(header));
    if (status == PV_OK) {
        (void)printf(
            "Requested field queued to the clipboard owner; owner lifetime is at most %u seconds\n",
            ttl
        );
    }
    return status;
}

static pv_status rofi_prepare(rofi_job *const job)
{
    int input_socket[2] = { -1, -1 };
    int output_pipe[2] = { -1, -1 };
    pid_t pid;

    *job = (rofi_job){ .input_fd = -1, .output_fd = -1, .pid = -1 };
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, input_socket) != 0 ||
        pipe2(output_pipe, O_CLOEXEC) != 0) {
        goto fail;
    }
    pid = fork();
    if (pid < 0) {
        goto fail;
    }
    if (pid == 0) {
        if (dup2(input_socket[0], STDIN_FILENO) < 0 || dup2(output_pipe[1], STDOUT_FILENO) < 0) {
            _exit(126);
        }
        (void)close(input_socket[0]);
        (void)close(input_socket[1]);
        (void)close(output_pipe[0]);
        (void)close(output_pipe[1]);
        execl("/usr/bin/rofi", "rofi", "-dmenu", "-i", "-p", "PVault", (char *)NULL);
        _exit(127);
    }
    (void)close(input_socket[0]);
    (void)close(output_pipe[1]);
    job->input_fd = input_socket[1];
    job->output_fd = output_pipe[0];
    job->pid = pid;
    return PV_OK;

fail:
    if (input_socket[0] >= 0) (void)close(input_socket[0]);
    if (input_socket[1] >= 0) (void)close(input_socket[1]);
    if (output_pipe[0] >= 0) (void)close(output_pipe[0]);
    if (output_pipe[1] >= 0) (void)close(output_pipe[1]);
    return PV_ERR_EXTERNAL;
}

static void rofi_cancel(rofi_job *const job)
{
    if (job->input_fd >= 0) (void)close(job->input_fd);
    if (job->output_fd >= 0) (void)close(job->output_fd);
    if (job->pid > 0) {
        (void)kill(job->pid, SIGTERM);
        (void)waitpid(job->pid, NULL, 0);
    }
    *job = (rofi_job){ .input_fd = -1, .output_fd = -1, .pid = -1 };
}

static pv_status rofi_select(rofi_job *const job, pv_vault *const vault, pv_record **const selected)
{
    size_t i;
    char response[PV_MAX_TITLE + 64U];
    size_t used = 0U;
    pv_status status = PV_ERR_NOT_FOUND;

    for (i = 0U; i < vault->record_count; ++i) {
        char id[PV_RECORD_ID_BYTES * 2U + 1U];
        char suffix[PV_RECORD_ID_BYTES * 2U + 3U];
        int suffix_length;

        if ((vault->records[i].flags & PV_RECORD_DELETED) != 0U) {
            continue;
        }
        pv_hex_encode(vault->records[i].id, PV_RECORD_ID_BYTES, id, sizeof(id));
        suffix_length = snprintf(suffix, sizeof(suffix), "\t%s\n", id);
        if (suffix_length < 0 || (size_t)suffix_length >= sizeof(suffix) ||
            !socket_write_title(job->input_fd, &vault->records[i].title) ||
            !socket_write_all(job->input_fd, suffix, (size_t)suffix_length)) {
            rofi_cancel(job);
            return PV_ERR_EXTERNAL;
        }
    }
    (void)close(job->input_fd);
    job->input_fd = -1;
    while (used + 1U < sizeof(response)) {
        const ssize_t got = read(job->output_fd, response + used, sizeof(response) - used - 1U);
        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            break;
        }
        used += (size_t)got;
    }
    response[used] = '\0';
    (void)close(job->output_fd);
    job->output_fd = -1;
    (void)waitpid(job->pid, NULL, 0);
    job->pid = -1;
    if (used > 0U) {
        char *tab = strrchr(response, '\t');
        if (tab != NULL) {
            uint8_t id[PV_RECORD_ID_BYTES];
            char *newline;
            ++tab;
            newline = strpbrk(tab, "\r\n");
            if (newline != NULL) {
                *newline = '\0';
            }
            if (pv_hex_decode(tab, id, sizeof(id))) {
                *selected = pv_model_find_id(vault, id);
                status = *selected == NULL ? PV_ERR_NOT_FOUND : PV_OK;
            }
            sodium_memzero(id, sizeof(id));
        }
    }
    sodium_memzero(response, sizeof(response));
    return status;
}

static pv_status command_pick(pv_cli_context *const context, const bool copy, const bool rofi)
{
    pv_clipboard_job clip_job = {
        .write_fd = -1,
        .control_fd = -1,
        .supervisor_fd = -1,
        .supervisor_pid = -1
    };
    rofi_job rofi_process = { .input_fd = -1, .output_fd = -1, .pid = -1 };
    bool clip_ready = false;
    bool rofi_ready = false;
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    pv_record *selected = NULL;
    pv_status status;

    if (copy) {
        status = pv_clipboard_prepare(&clip_job, context->config.clipboard_ttl);
        if (status != PV_OK) return status;
        clip_ready = true;
    }
    if (rofi) {
        status = rofi_prepare(&rofi_process);
        if (status != PV_OK) {
            if (clip_ready) pv_clipboard_cancel(&clip_job);
            return status;
        }
        rofi_ready = true;
    }
    status = open_password_vault(context, &vault, &header);
    if (status == PV_OK) {
        status = rofi ? rofi_select(&rofi_process, &vault, &selected) : pv_ui_pick_internal(&vault, &selected);
        rofi_ready = false;
    }
    if (status == PV_OK && copy) {
        status = selected->password.len == 0U
            ? PV_ERR_NOT_FOUND
            : pv_clipboard_send(&clip_job, selected->password.data, selected->password.len);
        clip_ready = false;
    } else if (status == PV_OK) {
        show_record(selected);
    }
    if (clip_ready) pv_clipboard_cancel(&clip_job);
    if (rofi_ready) rofi_cancel(&rofi_process);
    if (vault.arena.base != NULL) pv_model_destroy(&vault);
    sodium_memzero(&header, sizeof(header));
    return status;
}

static pv_status command_generate(const unsigned length, const unsigned ttl)
{
    pv_clipboard_job job;
    pv_buffer password = { 0 };
    pv_status status;

    status = pv_clipboard_prepare(&job, ttl);
    if (status == PV_OK) {
        status = generate_password(length, &password);
    }
    if (status == PV_OK) {
        status = pv_clipboard_send(&job, password.data, password.len);
    } else {
        pv_clipboard_cancel(&job);
    }
    pv_buffer_secure_free(&password);
    if (status == PV_OK) {
        (void)printf(
            "Generated %u-character password and queued it to the clipboard owner; "
            "owner lifetime is at most %u seconds\n",
            length,
            ttl
        );
    }
    return status;
}

static pv_status command_passwd(pv_cli_context *const context, const char *const recovery_file)
{
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    pv_buffer new_password = { 0 };
    pv_buffer encoded_recovery = { 0 };
    pv_buffer recovery_key = { 0 };
    pv_status status;

    if (recovery_file == NULL) {
        status = open_password_vault(context, &vault, &header);
    } else {
        uint8_t header_bytes[PV_FILE_HEADER_LEN];
        int fd;
        status = pv_secure_buffer_alloc(&encoded_recovery, PV_RECOVERY_TEXT_MAX);
        if (status == PV_OK) {
            status = pv_secure_buffer_alloc(&recovery_key, PV_RECOVERY_KEY_BYTES);
        }
        if (status == PV_OK) {
            status = pv_recovery_read_file(
                recovery_file,
                (char *)encoded_recovery.data,
                encoded_recovery.len
            );
        }
        fd = open(context->config.vault_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (status == PV_OK) {
            status = fd < 0 ? PV_ERR_IO : read_exact(fd, header_bytes, sizeof(header_bytes));
        }
        if (fd >= 0) (void)close(fd);
        if (status == PV_OK) status = pv_header_decode(header_bytes, &header);
        if (status == PV_OK) {
            status = pv_recovery_decode(
                (const char *)encoded_recovery.data,
                header.vault_id,
                recovery_key.data
            );
        }
        if (status == PV_OK) {
            pv_buffer_secure_free(&encoded_recovery);
            status = pv_store_open_recovery_consume(
                context->config.vault_path,
                &recovery_key,
                &vault,
                &header
            );
        }
        sodium_memzero(header_bytes, sizeof(header_bytes));
    }
    if (status == PV_OK) {
        status = pv_secure_read_secret("New master password: ", &new_password, true);
    }
    if (status == PV_OK) status = validate_new_master_password(&new_password);
    if (status == PV_OK) status = pv_crypto_rewrap_password(&header, new_password.data, new_password.len, vault.vmk);
    pv_buffer_secure_free(&new_password);
    if (status == PV_OK) {
        vault.dirty = true;
        status = pv_store_save(&vault, &header, context->config.backup_retention);
    }
    if (status == PV_OK) {
        (void)printf("Master password updated\n");
    } else if (status == PV_ERR_DURABILITY) {
        (void)printf("Password update reached the vault; verify both old and new passwords\n");
    }
    pv_buffer_secure_free(&encoded_recovery);
    pv_buffer_secure_free(&recovery_key);
    if (vault.arena.base != NULL) pv_model_destroy(&vault);
    sodium_memzero(&header, sizeof(header));
    return status;
}

static pv_status command_recovery_rotate(pv_cli_context *const context, const char *const output)
{
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    pv_buffer recovery_key = { 0 };
    pv_buffer encoded = { 0 };
    bool output_created = false;
    pv_status status;

    status = pv_secure_buffer_alloc(&recovery_key, PV_RECOVERY_KEY_BYTES);
    if (status == PV_OK) status = pv_secure_buffer_alloc(&encoded, PV_RECOVERY_TEXT_MAX);
    if (status == PV_OK) status = open_password_vault(context, &vault, &header);
    if (status == PV_OK) {
        randombytes_buf(recovery_key.data, recovery_key.len);
        status = pv_recovery_encode(
            vault.vault_id,
            recovery_key.data,
            (char *)encoded.data,
            encoded.len
        );
    }
    if (status == PV_OK) {
        status = pv_recovery_write_file(output, (const char *)encoded.data, vault.vault_id);
        output_created = status == PV_OK;
    }
    if (status == PV_OK) status = pv_crypto_rewrap_recovery(&header, recovery_key.data, vault.vmk);
    if (status == PV_OK) {
        vault.dirty = true;
        status = pv_store_save(&vault, &header, context->config.backup_retention);
    }
    if (status != PV_OK && status != PV_ERR_DURABILITY && output_created) (void)unlink(output);
    if (output_created && status_committed(status)) {
        if (status == PV_OK) {
            (void)printf(
                "Recovery key rotated; new key written to the requested output path.\n"
                "Move it to separate offline storage. The previous key is now invalid.\n"
            );
        } else {
            (void)printf(
                "Recovery update reached the vault; new key written to the requested output path.\n"
                "Keep both old and new recovery keys until both paths are verified.\n"
            );
        }
    }
    pv_buffer_secure_free(&recovery_key);
    pv_buffer_secure_free(&encoded);
    if (vault.arena.base != NULL) pv_model_destroy(&vault);
    sodium_memzero(&header, sizeof(header));
    return status;
}

static pv_status command_backup(pv_cli_context *const context, const char *const output)
{
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    pv_status status = open_password_vault(context, &vault, &header);
    if (status == PV_OK) {
        status = pv_store_backup(context->config.vault_path, output, vault.source_hash);
    }
    if (status == PV_OK) {
        (void)printf("Encrypted backup written to the requested output path.\n");
    }
    if (vault.arena.base != NULL) pv_model_destroy(&vault);
    sodium_memzero(&header, sizeof(header));
    return status;
}

static pv_status command_restore(pv_cli_context *const context, const char *const backup)
{
    pv_buffer password = { 0 };
    pv_vault verification = { 0 };
    pv_file_header header = { 0 };
    bool confirmed = false;
    bool cancelled = false;
    pv_status status;

    status = pv_secure_read_secret("Master password for backup: ", &password, false);
    if (status == PV_OK) {
        status = pv_store_open_password_consume(
            backup,
            &password,
            &verification,
            &header
        );
    }
    if (status == PV_OK) {
        (void)printf(
            "Warning: restore rolls back records, the master-password slot, and the recovery-key slot.\n"
            "Keep current and historical credentials until the restored vault is verified.\n"
        );
        status = pv_tty_confirm("Restore this authenticated backup? [y/N]: ", &confirmed);
    }
    if (status == PV_OK && !confirmed) {
        cancelled = true;
        (void)printf("Restore cancelled\n");
    }
    if (status == PV_OK && !cancelled) {
        status = pv_store_restore(context->config.vault_path, backup, verification.source_hash);
    }
    if (!cancelled && status_committed(status)) {
        (void)printf("Vault restored from the authenticated backup.\n");
    }
    pv_buffer_secure_free(&password);
    if (verification.arena.base != NULL) pv_model_destroy(&verification);
    sodium_memzero(&header, sizeof(header));
    return status;
}

static void print_snapshot_identity(
    const pv_file_header *const header,
    const pv_vault *const vault
)
{
    char vault_id[PV_VAULT_ID_BYTES * 2U + 1U];
    char hash[crypto_generichash_BYTES * 2U + 1U];

    pv_hex_encode(header->vault_id, PV_VAULT_ID_BYTES, vault_id, sizeof(vault_id));
    pv_hex_encode(vault->source_hash, sizeof(vault->source_hash), hash, sizeof(hash));
    (void)printf(
        "Authenticated snapshot\n"
        "Format: %u.%u\n"
        "Vault ID: %s\n"
        "Generation: %llu\n"
        "Record count: %zu\n"
        "Snapshot hash (BLAKE2b-256): %s\n",
        (unsigned)header->major,
        (unsigned)header->minor,
        vault_id,
        (unsigned long long)vault->generation,
        vault->record_count,
        hash
    );
}

static pv_status command_rescue_inspect(const char *const snapshot)
{
    pv_file_header header = { 0 };
    size_t ciphertext_len = 0U;
    char vault_id[PV_VAULT_ID_BYTES * 2U + 1U];
    pv_status status;

    status = pv_store_inspect(snapshot, &header, &ciphertext_len);
    if (status == PV_OK) {
        pv_hex_encode(header.vault_id, sizeof(header.vault_id), vault_id, sizeof(vault_id));
        (void)printf(
            "UNAUTHENTICATED snapshot metadata\n"
            "Do not use these values for recovery decisions until the snapshot is verified.\n"
            "Format (UNAUTHENTICATED): %u.%u\n"
            "Vault ID (UNAUTHENTICATED): %s\n"
            "Ciphertext bytes (UNAUTHENTICATED): %zu\n",
            (unsigned)header.major,
            (unsigned)header.minor,
            vault_id,
            ciphertext_len
        );
    }
    sodium_memzero(&header, sizeof(header));
    return status;
}

static pv_status open_authenticated_snapshot(
    const char *const snapshot,
    const char *const recovery_file,
    pv_vault *const vault,
    pv_file_header *const header
)
{
    pv_file_header inspected_header = { 0 };
    size_t ciphertext_len = 0U;
    pv_buffer password = { 0 };
    pv_buffer encoded_recovery = { 0 };
    pv_buffer recovery_key = { 0 };
    pv_status status;

    status = pv_store_inspect(snapshot, &inspected_header, &ciphertext_len);
    if (status == PV_OK && recovery_file == NULL) {
        status = pv_secure_read_secret("Master password for snapshot: ", &password, false);
        if (status == PV_OK) {
            status = pv_store_open_password_consume(
                snapshot,
                &password,
                vault,
                header
            );
        }
    } else if (status == PV_OK) {
        status = pv_secure_buffer_alloc(&encoded_recovery, PV_RECOVERY_TEXT_MAX);
        if (status == PV_OK) {
            status = pv_secure_buffer_alloc(&recovery_key, PV_RECOVERY_KEY_BYTES);
        }
        if (status == PV_OK) {
            status = pv_recovery_read_file(
                recovery_file,
                (char *)encoded_recovery.data,
                encoded_recovery.len
            );
        }
        if (status == PV_OK) {
            status = pv_recovery_decode(
                (const char *)encoded_recovery.data,
                inspected_header.vault_id,
                recovery_key.data
            );
        }
        if (status == PV_OK) {
            pv_buffer_secure_free(&encoded_recovery);
            status = pv_store_open_recovery_consume(
                snapshot,
                &recovery_key,
                vault,
                header
            );
        }
    }
    pv_buffer_secure_free(&password);
    pv_buffer_secure_free(&encoded_recovery);
    pv_buffer_secure_free(&recovery_key);
    sodium_memzero(&inspected_header, sizeof(inspected_header));
    return status;
}

static pv_status command_rescue_verify(
    const char *const snapshot,
    const char *const recovery_file
)
{
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    pv_status status;

    status = open_authenticated_snapshot(snapshot, recovery_file, &vault, &header);
    if (status == PV_OK) {
        print_snapshot_identity(&header, &vault);
    }
    if (vault.arena.base != NULL) {
        pv_model_destroy(&vault);
    }
    sodium_memzero(&header, sizeof(header));
    return status;
}

static pv_status command_rescue_copy(
    const char *const snapshot,
    const char *const output,
    const char *const recovery_file,
    const bool rollback
)
{
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    pv_status status;

    status = open_authenticated_snapshot(snapshot, recovery_file, &vault, &header);
    if (status == PV_OK) {
        status = pv_store_recover_authenticated(snapshot, output, vault.source_hash);
    }
    if (status == PV_OK) {
        (void)printf(
            rollback
                ? "Authenticated rollback copy written in mode 0400.\n"
                  "The requested output path contains the byte-exact encrypted copy.\n"
                  "The active vault and source snapshot were left unchanged.\n"
                : "Authenticated recovery copy written in mode 0400.\n"
                  "The requested output path contains the byte-exact encrypted copy.\n"
                  "The active vault and source snapshot were left unchanged.\n"
        );
    } else if (status == PV_ERR_DURABILITY) {
        (void)fprintf(
            stderr,
            "%s copy publication may have occurred, but the requested output is not verified.\n"
            "The active vault and source snapshot were left unchanged.\n"
            "Verify the requested output path with rescue verify before using this copy.\n",
            rollback ? "Rollback" : "Recovery"
        );
    }
    if (vault.arena.base != NULL) {
        pv_model_destroy(&vault);
    }
    sodium_memzero(&header, sizeof(header));
    return status;
}

static pv_status parse_rescue_command(const int argc, char **const argv)
{
    const char *recovery_file = NULL;
    const char *output = NULL;
    int i;

    if (argc == 2 && strcmp(argv[0], "inspect") == 0) {
        return command_rescue_inspect(argv[1]);
    }
    if (argc >= 2 && strcmp(argv[0], "verify") == 0) {
        for (i = 2; i < argc; ++i) {
            if (strcmp(argv[i], "--recovery") == 0 && recovery_file == NULL && i + 1 < argc) {
                recovery_file = argv[++i];
            } else {
                return PV_ERR_USAGE;
            }
        }
        return command_rescue_verify(argv[1], recovery_file);
    }
    if (argc >= 2 && strcmp(argv[0], "recover") == 0) {
        for (i = 2; i < argc; ++i) {
            if (strcmp(argv[i], "--output") == 0 && output == NULL && i + 1 < argc) {
                output = argv[++i];
            } else if (strcmp(argv[i], "--recovery") == 0 && recovery_file == NULL && i + 1 < argc) {
                recovery_file = argv[++i];
            } else {
                return PV_ERR_USAGE;
            }
        }
        return output == NULL
            ? PV_ERR_USAGE
            : command_rescue_copy(argv[1], output, recovery_file, false);
    }
    return PV_ERR_USAGE;
}

static pv_status parse_rollback_command(const int argc, char **const argv)
{
    const char *recovery_file = NULL;
    const char *output = NULL;
    int i;

    if (argc < 1) {
        return PV_ERR_USAGE;
    }
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--output") == 0 && output == NULL && i + 1 < argc) {
            output = argv[++i];
        } else if (strcmp(argv[i], "--recovery") == 0 && recovery_file == NULL && i + 1 < argc) {
            recovery_file = argv[++i];
        } else {
            return PV_ERR_USAGE;
        }
    }
    return output == NULL
        ? PV_ERR_USAGE
        : command_rescue_copy(argv[0], output, recovery_file, true);
}

static pv_status command_doctor(pv_cli_context *const context)
{
    char message[256];
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    pv_status status = pv_store_doctor(context->config.vault_path, message, sizeof(message));
    (void)printf("%s\n", message);
    if (status == PV_OK) {
        status = open_password_vault(context, &vault, &header);
        if (status == PV_OK) (void)printf("authentication and payload validation OK\n");
    }
    if (vault.arena.base != NULL) pv_model_destroy(&vault);
    sodium_memzero(&header, sizeof(header));
    return status;
}

static pv_status command_config_check(void)
{
    pv_config verified;
    pv_status status;

    memset(&verified, 0, sizeof(verified));
    status = pv_config_load(&verified);
    if (status == PV_OK) {
        (void)printf(
            "Configuration check passed (private file or built-in defaults).\n"
        );
    }
    sodium_memzero(&verified, sizeof(verified));
    return status;
}

pv_status pv_cli_run(pv_cli_context *const context, int argc, char **argv)
{
    const char *command;

    if (context == NULL || argc < 2 || argv == NULL) {
        print_usage(stderr);
        return PV_ERR_USAGE;
    }
    ++argv;
    --argc;
    if (argc >= 2 && strcmp(argv[0], "--vault") == 0) {
        const size_t vault_path_len = strlen(argv[1]);

        if (argv[1][0] != '/' || vault_path_len >= sizeof(context->config.vault_path)) return PV_ERR_USAGE;
        (void)memcpy(context->config.vault_path, argv[1], vault_path_len + 1U);
        argv += 2;
        argc -= 2;
    }
    if (argc == 0) return PV_ERR_USAGE;
    command = argv[0];
    ++argv;
    --argc;
    if (strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0) {
        if (argc != 0) {
            return PV_ERR_USAGE;
        }
        print_usage(stdout);
        return PV_OK;
    }
    if (strcmp(command, "help") == 0) {
        if (argc == 0) {
            print_usage(stdout);
            return PV_OK;
        }
        if (argc <= 2 && print_command_usage(
                stdout,
                argv[0],
                argc == 2 ? argv[1] : NULL
            )) {
            return PV_OK;
        }
        return PV_ERR_USAGE;
    }
    if (strcmp(command, "--version") == 0) {
        if (argc != 0) {
            return PV_ERR_USAGE;
        }
        (void)printf(
            "pvault %d.%d.%d-%s\n",
            PVAULT_VERSION_MAJOR,
            PVAULT_VERSION_MINOR,
            PVAULT_VERSION_PATCH,
            PVAULT_VERSION_MATURITY
        );
        return PV_OK;
    }
    if (argc == 1 && strcmp(argv[0], "--help") == 0) {
        return print_command_usage(stdout, command, NULL) ? PV_OK : PV_ERR_USAGE;
    }
    if ((strcmp(command, "rescue") == 0 || strcmp(command, "recovery") == 0) &&
        argc == 2 && strcmp(argv[1], "--help") == 0) {
        return print_command_usage(stdout, command, argv[0]) ? PV_OK : PV_ERR_USAGE;
    }
    if (strcmp(command, "init") == 0) return command_init(context, argc, argv);
    if (strcmp(command, "config") == 0 && argc == 1 &&
        strcmp(argv[0], "check") == 0) {
        return command_config_check();
    }
    if (strcmp(command, "add") == 0 && argc == 0) return command_add(context);
    if (strcmp(command, "edit") == 0 && argc == 1) return command_edit(context, argv[0]);
    if (strcmp(command, "remove") == 0 && argc == 1) return command_remove(context, argv[0]);
    if (strcmp(command, "list") == 0 && argc <= 1) return command_list(context, argc == 1 ? argv[0] : NULL);
    if (strcmp(command, "show") == 0 && argc == 1) return command_show(context, argv[0]);
    if (strcmp(command, "shell") == 0 && argc == 0) return pv_shell_run(context);
    if (strcmp(command, "doctor") == 0 && argc == 0) return command_doctor(context);
    if (strcmp(command, "copy") == 0 && argc >= 1) {
        const char *field = "password";
        unsigned ttl = context->config.clipboard_ttl;
        int i;
        for (i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "--field") == 0 && i + 1 < argc) field = argv[++i];
            else if (strcmp(argv[i], "--ttl") == 0 && i + 1 < argc) {
                char *end = NULL;
                const unsigned long value = strtoul(argv[++i], &end, 10);
                if (end == argv[i] || *end != '\0' || value == 0U || value > 300U) return PV_ERR_USAGE;
                ttl = (unsigned)value;
            } else return PV_ERR_USAGE;
        }
        return command_copy(context, argv[0], field, ttl);
    }
    if (strcmp(command, "pick") == 0) {
        bool copy = false;
        bool rofi = context->config.picker_rofi;
        int i;
        for (i = 0; i < argc; ++i) {
            if (strcmp(argv[i], "--copy") == 0) copy = true;
            else if (strcmp(argv[i], "--rofi") == 0) rofi = true;
            else return PV_ERR_USAGE;
        }
        return command_pick(context, copy, rofi);
    }
    if (strcmp(command, "generate") == 0) {
        unsigned length = 24U;
        int i;
        for (i = 0; i < argc; ++i) {
            if (strcmp(argv[i], "--length") == 0 && i + 1 < argc) {
                char *end = NULL;
                const unsigned long value = strtoul(argv[++i], &end, 10);
                if (end == argv[i] || *end != '\0' || value < 12U || value > 256U) return PV_ERR_USAGE;
                length = (unsigned)value;
            } else if (strcmp(argv[i], "--copy") != 0) return PV_ERR_USAGE;
        }
        return command_generate(length, context->config.clipboard_ttl);
    }
    if (strcmp(command, "passwd") == 0) {
        const char *recovery = NULL;
        if (argc == 2 && strcmp(argv[0], "--recovery") == 0) recovery = argv[1];
        else if (argc != 0) return PV_ERR_USAGE;
        return command_passwd(context, recovery);
    }
    if (strcmp(command, "recovery") == 0 && argc == 3 && strcmp(argv[0], "rotate") == 0 && strcmp(argv[1], "--out") == 0) {
        return command_recovery_rotate(context, argv[2]);
    }
    if (strcmp(command, "backup") == 0 && argc == 2 && strcmp(argv[0], "--output") == 0) {
        return command_backup(context, argv[1]);
    }
    if (strcmp(command, "restore") == 0 && argc == 1) return command_restore(context, argv[0]);
    if (strcmp(command, "rescue") == 0) return parse_rescue_command(argc, argv);
    if (strcmp(command, "rollback") == 0) return parse_rollback_command(argc, argv);
    print_usage(stderr);
    return PV_ERR_USAGE;
}
