#include "cli.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#ifndef PVAULT_ROFI_EXECUTABLE
#define PVAULT_ROFI_EXECUTABLE "/usr/bin/rofi"
#endif

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

typedef struct rofi_entry {
    uint8_t token[8];
    pv_record *record;
} rofi_entry;

typedef enum copy_field_kind {
    COPY_FIELD_PASSWORD = 0,
    COPY_FIELD_USERNAME,
    COPY_FIELD_URL,
    COPY_FIELD_CUSTOM
} copy_field_kind;

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

static int waitpid_nointr(const pid_t pid, int *const status, const int options)
{
    int result;

    do {
        result = waitpid(pid, status, options);
    } while (result < 0 && errno == EINTR);
    return result;
}

static bool fd_write_all_no_sigpipe(const int fd, const void *const input, const size_t length)
{
    const uint8_t *cursor = input;
    size_t remaining = length;
    sigset_t blocked;
    sigset_t previous;
    sigset_t pending;
    bool pipe_was_pending;
    int saved_errno = 0;

    if (sigemptyset(&blocked) != 0 || sigaddset(&blocked, SIGPIPE) != 0 ||
        sigprocmask(SIG_BLOCK, &blocked, &previous) != 0) {
        return false;
    }
    if (sigpending(&pending) != 0) {
        saved_errno = errno;
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        errno = saved_errno;
        return false;
    }
    pipe_was_pending = sigismember(&pending, SIGPIPE) == 1;

    while (remaining > 0U) {
        const ssize_t written = write(fd, cursor, remaining);

        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            saved_errno = written < 0 ? errno : EIO;
            break;
        }
        cursor += (size_t)written;
        remaining -= (size_t)written;
    }
    if (saved_errno == EPIPE && !pipe_was_pending) {
        const struct timespec no_wait = { .tv_sec = 0, .tv_nsec = 0 };
        int waited;

        do {
            waited = sigtimedwait(&blocked, NULL, &no_wait);
        } while (waited < 0 && errno == EINTR);
    }
    if (sigprocmask(SIG_SETMASK, &previous, NULL) != 0 && saved_errno == 0) {
        saved_errno = errno;
    }
    if (saved_errno != 0) errno = saved_errno;
    return saved_errno == 0;
}

static void print_usage(FILE *const stream)
{
    (void)fprintf(
        stream,
        "Usage: pvault [--vault PATH] COMMAND [OPTIONS]\n"
        "Commands:\n"
        "  init --recovery-out PATH   Create a new vault\n"
        "  add                         Add a credential\n"
        "  edit                        Select and edit a credential\n"
        "  remove                      Select and delete a credential\n"
        "  list [--allow-redirect]     List credentials\n"
        "  show [--allow-redirect]     Select and show redacted record metadata\n"
        "  copy [--field FIELD]        Select and copy a field\n"
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
        usage = "Usage: pvault [--vault PATH] edit\n";
    } else if (strcmp(command, "remove") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] remove\n";
    } else if (strcmp(command, "list") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] list [--allow-redirect]\n";
    } else if (strcmp(command, "show") == 0 && topic == NULL) {
        usage = "Usage: pvault [--vault PATH] show [--allow-redirect]\n";
    } else if (strcmp(command, "copy") == 0 && topic == NULL) {
        usage =
            "Usage: pvault [--vault PATH] copy "
            "[--field password|username|url|custom] [--ttl SECONDS]\n";
    } else if (strcmp(command, "pick") == 0 && topic == NULL) {
        usage =
            "Usage: pvault [--vault PATH] pick "
            "[--copy] [--rofi] [--allow-redirect]\n";
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
            "       pvault rescue verify SNAPSHOT [--recovery FILE] [--allow-redirect]\n"
            "       pvault rescue recover SNAPSHOT --output PATH [--recovery FILE]\n";
    } else if (strcmp(command, "rescue") == 0 && topic != NULL &&
        strcmp(topic, "inspect") == 0) {
        usage = "Usage: pvault rescue inspect SNAPSHOT\n";
    } else if (strcmp(command, "rescue") == 0 && topic != NULL &&
        strcmp(topic, "verify") == 0) {
        usage =
            "Usage: pvault rescue verify SNAPSHOT "
            "[--recovery FILE] [--allow-redirect]\n";
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

static pv_status require_private_output(const bool allow_redirect)
{
    if (isatty(STDOUT_FILENO) || allow_redirect) {
        return PV_OK;
    }
    (void)fprintf(
        stderr,
        "pvault: refusing to emit decrypted record metadata to non-terminal stdout; "
        "repeat with --allow-redirect only for an intentional private destination\n"
    );
    return PV_ERR_USAGE;
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

static pv_status select_record_private(pv_vault *const vault, pv_record **const record)
{
    const pv_status status = pv_ui_pick_internal(vault, record);

    if (status == PV_ERR_NOT_FOUND) {
        (void)fprintf(stderr, "pvault: no record selected\n");
    }
    return status;
}

static pv_status reject_positional_selector(void)
{
    (void)fprintf(
        stderr,
        "pvault: positional record selectors are disabled because process arguments are public; "
        "use the interactive picker\n"
    );
    return PV_ERR_USAGE;
}

static pv_status tty_write_all(const int fd, const uint8_t *data, const size_t length)
{
    size_t written = 0U;

    while (written < length) {
        const ssize_t result = write(fd, data + written, length - written);

        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) return PV_ERR_IO;
        written += (size_t)result;
    }
    return PV_OK;
}

static pv_status tty_print_selected_title(const pv_record *const record)
{
    uint8_t sanitized[PV_MAX_TITLE];
    size_t sanitized_len = 0U;
    int fd;
    pv_status status = PV_OK;

    if (!pv_text_sanitize(
            &record->title,
            sanitized,
            sizeof(sanitized),
            &sanitized_len
        )) {
        return PV_ERR_STATE;
    }
    fd = open("/dev/tty", O_WRONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0 || dprintf(fd, "Selected for deletion: ") < 0) {
        status = PV_ERR_IO;
    }
    if (status == PV_OK) status = tty_write_all(fd, sanitized, sanitized_len);
    if (status == PV_OK && dprintf(fd, "\n") < 0) status = PV_ERR_IO;
    if (fd >= 0) (void)close(fd);
    sodium_memzero(sanitized, sizeof(sanitized));
    return status;
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
        (void)printf("Record added\n");
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

static pv_status command_edit(pv_cli_context *const context)
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
    status = select_record_private(&vault, &record);
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
        (void)printf("Record updated\n");
    }
    pv_buffer_secure_free(&field);
    pv_buffer_secure_free(&value);
    pv_model_destroy(&vault);
    sodium_memzero(&header, sizeof(header));
    return status;
}

static pv_status command_remove(pv_cli_context *const context)
{
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    pv_record *record;
    bool confirmed = false;
    bool cancelled = false;
    pv_status status;

    status = open_password_vault(context, &vault, &header);
    if (status == PV_OK) {
        status = select_record_private(&vault, &record);
    } else {
        record = NULL;
    }
    if (status == PV_OK) {
        status = tty_print_selected_title(record);
    }
    if (status == PV_OK) {
        status = pv_tty_confirm("Delete the selected record [y/N]: ", &confirmed);
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

static pv_status command_list(pv_cli_context *const context, const bool allow_redirect)
{
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    size_t i;
    size_t shown = 0U;
    pv_status status;

    status = require_private_output(allow_redirect);
    if (status == PV_OK) {
        status = open_password_vault(context, &vault, &header);
    }
    if (status != PV_OK) {
        return status;
    }
    for (i = 0U; i < vault.record_count; ++i) {
        pv_record *const record = &vault.records[i];
        if ((record->flags & PV_RECORD_DELETED) != 0U) {
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

static pv_status command_show(pv_cli_context *const context, const bool allow_redirect)
{
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    pv_status status;
    pv_record *record;

    status = require_private_output(allow_redirect);
    if (status == PV_OK) {
        status = open_password_vault(context, &vault, &header);
    }
    if (status == PV_OK) {
        status = select_record_private(&vault, &record);
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

static pv_status record_field_view(
    const pv_record *const record,
    const copy_field_kind field,
    pv_view *const view
)
{
    if (field == COPY_FIELD_PASSWORD) {
        *view = (pv_view){ record->password.data, record->password.len };
    } else if (field == COPY_FIELD_USERNAME) {
        *view = (pv_view){ record->username.data, record->username.len };
    } else if (field == COPY_FIELD_URL && record->url_count > 0U) {
        *view = (pv_view){ record->urls[0].data, record->urls[0].len };
    } else {
        return PV_ERR_NOT_FOUND;
    }
    return view->len == 0U ? PV_ERR_NOT_FOUND : PV_OK;
}

static pv_status select_custom_field_view(const pv_record *const record, pv_view *const view)
{
    uint8_t sanitized[PV_MAX_FIELD_NAME];
    size_t index;
    unsigned selection = 0U;
    int fd;
    pv_status status = PV_OK;

    if (record->field_count == 0U || record->field_count > (size_t)UINT_MAX) {
        return PV_ERR_NOT_FOUND;
    }
    fd = open("/dev/tty", O_WRONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0 || dprintf(fd, "Custom fields:\n") < 0) status = PV_ERR_IO;
    for (index = 0U; status == PV_OK && index < record->field_count; ++index) {
        size_t sanitized_len = 0U;

        if (dprintf(fd, "  %zu. ", index + 1U) < 0 ||
            !pv_text_sanitize(
                &record->fields[index].name,
                sanitized,
                sizeof(sanitized),
                &sanitized_len
            )) {
            status = PV_ERR_IO;
            break;
        }
        status = tty_write_all(fd, sanitized, sanitized_len);
        sodium_memzero(sanitized, sizeof(sanitized));
        if (status == PV_OK && dprintf(fd, "\n") < 0) status = PV_ERR_IO;
    }
    sodium_memzero(sanitized, sizeof(sanitized));
    if (fd >= 0) (void)close(fd);
    if (status == PV_OK) {
        status = pv_tty_read_unsigned(
            "Custom field number: ",
            (unsigned)record->field_count,
            0U,
            &selection
        );
    }
    if (status == PV_OK && selection == 0U) status = PV_ERR_USAGE;
    if (status == PV_OK) {
        const pv_slice *const value = &record->fields[selection - 1U].value;

        *view = (pv_view){ value->data, value->len };
        if (view->len == 0U) status = PV_ERR_NOT_FOUND;
    }
    return status;
}

static pv_status command_copy(
    pv_cli_context *const context,
    const copy_field_kind field,
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
        status = select_record_private(&vault, &record);
    } else {
        record = NULL;
    }
    if (status == PV_OK) {
        status = field == COPY_FIELD_CUSTOM
            ? select_custom_field_view(record, &view)
            : record_field_view(record, field, &view);
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

static char *rofi_environment_entry(const char *const name)
{
    const size_t name_len = strlen(name);
    size_t index;

    for (index = 0U; environ != NULL && environ[index] != NULL; ++index) {
        if (strncmp(environ[index], name, name_len) == 0 && environ[index][name_len] == '=') {
            return environ[index];
        }
    }
    return NULL;
}

static void rofi_close_inherited_fds(void)
{
    struct rlimit limit;
    long maximum;
    int fd;

    if (close_range(3U, UINT_MAX, 0) == 0) return;
    maximum = sysconf(_SC_OPEN_MAX);
    if ((maximum < 0L || maximum > (long)INT_MAX) &&
        getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur <= (rlim_t)INT_MAX) {
        maximum = (long)limit.rlim_cur;
    }
    if (maximum < 0L || maximum > (long)INT_MAX) maximum = 65536L;
    for (fd = 3; fd < (int)maximum; ++fd) {
        (void)close(fd);
    }
}

static bool rofi_reset_signal_state(void)
{
    static const int signals[] = {
        SIGINT,
        SIGTERM,
        SIGHUP,
        SIGQUIT,
        SIGTSTP,
        SIGPIPE,
        SIGCHLD
    };
    struct sigaction default_action;
    sigset_t guarded;
    sigset_t empty;
    size_t index;

    memset(&default_action, 0, sizeof(default_action));
    default_action.sa_handler = SIG_DFL;
    if (sigemptyset(&default_action.sa_mask) != 0 || sigemptyset(&guarded) != 0 ||
        sigemptyset(&empty) != 0) {
        return false;
    }
    for (index = 0U; index < sizeof(signals) / sizeof(signals[0]); ++index) {
        if (sigaddset(&guarded, signals[index]) != 0) return false;
    }
    if (sigprocmask(SIG_BLOCK, &guarded, NULL) != 0) return false;
    for (index = 0U; index < sizeof(signals) / sizeof(signals[0]); ++index) {
        if (sigaction(signals[index], &default_action, NULL) != 0) return false;
    }
    return sigprocmask(SIG_SETMASK, &empty, NULL) == 0;
}

static bool rofi_wait_deadline(const pid_t pid, const unsigned attempts)
{
    const struct timespec interval = { .tv_sec = 0, .tv_nsec = 10000000L };
    unsigned attempt;

    for (attempt = 0U; attempt < attempts; ++attempt) {
        const int result = waitpid_nointr(pid, NULL, WNOHANG);

        if (result == pid || (result < 0 && errno == ECHILD)) return true;
        if (result < 0) return false;
        (void)nanosleep(&interval, NULL);
    }
    return false;
}

static void rofi_terminate_and_reap(const pid_t pid)
{
    if (pid <= 0 || rofi_wait_deadline(pid, 1U)) return;
    (void)kill(pid, SIGTERM);
    if (rofi_wait_deadline(pid, 50U)) return;
    (void)kill(pid, SIGKILL);
    (void)waitpid_nointr(pid, NULL, 0);
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
        static const char *const allowed_names[] = {
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XDG_RUNTIME_DIR",
            "HOME",
            "XAUTHORITY",
            "XDG_CONFIG_HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE"
        };
        char safe_path[] = "PATH=/usr/bin:/bin";
        char *environment[sizeof(allowed_names) / sizeof(allowed_names[0]) + 2U];
        char argument_0[] = "rofi";
        char argument_1[] = "-dmenu";
        char argument_2[] = "-i";
        char argument_3[] = "-p";
        char argument_4[] = "PVault";
        char *arguments[] = {
            argument_0,
            argument_1,
            argument_2,
            argument_3,
            argument_4,
            NULL
        };
        size_t allowed_index;
        size_t environment_count = 1U;

        environment[0] = safe_path;

        if (dup2(input_socket[0], STDIN_FILENO) < 0 || dup2(output_pipe[1], STDOUT_FILENO) < 0) {
            _exit(126);
        }
        (void)close(input_socket[0]);
        (void)close(input_socket[1]);
        (void)close(output_pipe[0]);
        (void)close(output_pipe[1]);
        if (!rofi_reset_signal_state()) _exit(126);
        rofi_close_inherited_fds();
        for (allowed_index = 0U;
             allowed_index < sizeof(allowed_names) / sizeof(allowed_names[0]);
             ++allowed_index) {
            char *const entry = rofi_environment_entry(allowed_names[allowed_index]);

            if (entry != NULL) environment[environment_count++] = entry;
        }
        environment[environment_count] = NULL;
        execve(PVAULT_ROFI_EXECUTABLE, arguments, environment);
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
        rofi_terminate_and_reap(job->pid);
    }
    *job = (rofi_job){ .input_fd = -1, .output_fd = -1, .pid = -1 };
}

static bool rofi_token_unique(
    const rofi_entry *const entries,
    const size_t entry_count,
    const uint8_t token[8]
)
{
    size_t index;

    for (index = 0U; index < entry_count; ++index) {
        if (sodium_memcmp(entries[index].token, token, sizeof(entries[index].token)) == 0) {
            return false;
        }
    }
    return true;
}

static pv_status rofi_select(rofi_job *const job, pv_vault *const vault, pv_record **const selected)
{
    rofi_entry *entries;
    size_t entry_count = 0U;
    size_t i;
    char response[PV_MAX_TITLE + 64U];
    size_t used = 0U;
    pv_status status = PV_ERR_NOT_FOUND;

    entries = calloc(vault->record_count, sizeof(*entries));
    if (entries == NULL && vault->record_count != 0U) {
        rofi_cancel(job);
        return PV_ERR_NOMEM;
    }
    for (i = 0U; i < vault->record_count; ++i) {
        uint8_t safe_title[PV_MAX_TITLE];
        size_t safe_title_len = 0U;
        char token_hex[sizeof(entries[entry_count].token) * 2U + 1U];
        char suffix[sizeof(token_hex) + 2U];
        int suffix_length;
        bool sanitized_ok;
        bool title_sent;
        bool suffix_sent;
        bool sent;

        if ((vault->records[i].flags & PV_RECORD_DELETED) != 0U) {
            continue;
        }
        do {
            randombytes_buf(entries[entry_count].token, sizeof(entries[entry_count].token));
        } while (!rofi_token_unique(entries, entry_count, entries[entry_count].token));
        entries[entry_count].record = &vault->records[i];
        pv_hex_encode(
            entries[entry_count].token,
            sizeof(entries[entry_count].token),
            token_hex,
            sizeof(token_hex)
        );
        suffix_length = snprintf(suffix, sizeof(suffix), "\t%s\n", token_hex);
        sanitized_ok = pv_text_sanitize(
            &vault->records[i].title,
            safe_title,
            sizeof(safe_title),
            &safe_title_len
        );
        title_sent = sanitized_ok &&
            fd_write_all_no_sigpipe(job->input_fd, safe_title, safe_title_len);
        suffix_sent = suffix_length >= 0 && (size_t)suffix_length < sizeof(suffix) &&
            title_sent && fd_write_all_no_sigpipe(job->input_fd, suffix, (size_t)suffix_length);
        sent = sanitized_ok && title_sent && suffix_sent;
        sodium_memzero(safe_title, sizeof(safe_title));
        sodium_memzero(token_hex, sizeof(token_hex));
        sodium_memzero(suffix, sizeof(suffix));
        if (!sent) {
            rofi_cancel(job);
            status = PV_ERR_EXTERNAL;
            goto cleanup;
        }
        ++entry_count;
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
    if (!rofi_wait_deadline(job->pid, 50U)) {
        rofi_terminate_and_reap(job->pid);
    }
    job->pid = -1;
    if (used > 1U && response[used - 1U] == '\n') {
        char *const tab = strchr(response, '\t');
        size_t token_length;
        uint8_t token[sizeof(entries[0].token)];

        response[--used] = '\0';
        if (used > 0U && response[used - 1U] == '\r') {
            response[--used] = '\0';
        }
        if (tab != NULL && strchr(tab + 1, '\t') == NULL &&
            strpbrk(response, "\r\n") == NULL) {
            token_length = used - (size_t)(tab + 1 - response);
            if (token_length == sizeof(token) * 2U &&
                pv_hex_decode(tab + 1, token, sizeof(token))) {
                for (i = 0U; i < entry_count; ++i) {
                    if (sodium_memcmp(entries[i].token, token, sizeof(token)) == 0) {
                        *selected = entries[i].record;
                        status = PV_OK;
                        break;
                    }
                }
            }
        }
        sodium_memzero(token, sizeof(token));
    }
cleanup:
    if (entries != NULL) sodium_memzero(entries, vault->record_count * sizeof(*entries));
    free(entries);
    sodium_memzero(response, sizeof(response));
    return status;
}

static pv_status command_pick(
    pv_cli_context *const context,
    const bool copy,
    const bool rofi,
    const bool allow_redirect
)
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

    status = copy ? PV_OK : require_private_output(allow_redirect);
    if (status != PV_OK) return status;
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
    const char *const recovery_file,
    const bool allow_redirect
)
{
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    pv_status status;

    status = require_private_output(allow_redirect);
    if (status == PV_OK) {
        status = open_authenticated_snapshot(snapshot, recovery_file, &vault, &header);
    }
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
    bool allow_redirect = false;
    int i;

    if (argc == 2 && strcmp(argv[0], "inspect") == 0) {
        return command_rescue_inspect(argv[1]);
    }
    if (argc >= 2 && strcmp(argv[0], "verify") == 0) {
        for (i = 2; i < argc; ++i) {
            if (strcmp(argv[i], "--recovery") == 0 && recovery_file == NULL && i + 1 < argc) {
                recovery_file = argv[++i];
            } else if (strcmp(argv[i], "--allow-redirect") == 0 && !allow_redirect) {
                allow_redirect = true;
            } else {
                return PV_ERR_USAGE;
            }
        }
        return command_rescue_verify(argv[1], recovery_file, allow_redirect);
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
    if (strcmp(command, "edit") == 0) {
        return argc == 0 ? command_edit(context) : reject_positional_selector();
    }
    if (strcmp(command, "remove") == 0) {
        return argc == 0 ? command_remove(context) : reject_positional_selector();
    }
    if (strcmp(command, "list") == 0) {
        if (argc == 0) return command_list(context, false);
        if (argc == 1 && strcmp(argv[0], "--allow-redirect") == 0) {
            return command_list(context, true);
        }
        return reject_positional_selector();
    }
    if (strcmp(command, "show") == 0) {
        if (argc == 0) return command_show(context, false);
        if (argc == 1 && strcmp(argv[0], "--allow-redirect") == 0) {
            return command_show(context, true);
        }
        return reject_positional_selector();
    }
    if (strcmp(command, "shell") == 0 && argc == 0) return pv_shell_run(context);
    if (strcmp(command, "doctor") == 0 && argc == 0) return command_doctor(context);
    if (strcmp(command, "copy") == 0) {
        copy_field_kind field = COPY_FIELD_PASSWORD;
        unsigned ttl = context->config.clipboard_ttl;
        int i;
        for (i = 0; i < argc; ++i) {
            if (strcmp(argv[i], "--field") == 0 && i + 1 < argc) {
                const char *const value = argv[++i];

                if (strcmp(value, "password") == 0) field = COPY_FIELD_PASSWORD;
                else if (strcmp(value, "username") == 0) field = COPY_FIELD_USERNAME;
                else if (strcmp(value, "url") == 0) field = COPY_FIELD_URL;
                else if (strcmp(value, "custom") == 0) field = COPY_FIELD_CUSTOM;
                else return PV_ERR_USAGE;
            } else if (strcmp(argv[i], "--ttl") == 0 && i + 1 < argc) {
                char *end = NULL;
                const unsigned long value = strtoul(argv[++i], &end, 10);
                if (end == argv[i] || *end != '\0' || value == 0U || value > 300U) return PV_ERR_USAGE;
                ttl = (unsigned)value;
            } else if (argv[i][0] != '-') {
                return reject_positional_selector();
            } else {
                return PV_ERR_USAGE;
            }
        }
        return command_copy(context, field, ttl);
    }
    if (strcmp(command, "pick") == 0) {
        bool copy = false;
        bool rofi = context->config.picker_rofi;
        bool allow_redirect = false;
        int i;
        for (i = 0; i < argc; ++i) {
            if (strcmp(argv[i], "--copy") == 0) copy = true;
            else if (strcmp(argv[i], "--rofi") == 0) rofi = true;
            else if (strcmp(argv[i], "--allow-redirect") == 0) allow_redirect = true;
            else return PV_ERR_USAGE;
        }
        if (copy && allow_redirect) return PV_ERR_USAGE;
        return command_pick(context, copy, rofi, allow_redirect);
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
