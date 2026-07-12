#include "cli.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void shell_print_slice(const pv_slice *const slice)
{
    pv_text_fprint(stdout, slice);
}

static void shell_list(const pv_vault *const vault)
{
    size_t i;

    for (i = 0U; i < vault->record_count; ++i) {
        char id[PV_RECORD_ID_BYTES * 2U + 1U];
        const pv_record *const record = &vault->records[i];
        if ((record->flags & PV_RECORD_DELETED) != 0U) {
            continue;
        }
        pv_hex_encode(record->id, PV_RECORD_ID_BYTES, id, sizeof(id));
        (void)printf("%.8s  ", id);
        shell_print_slice(&record->title);
        (void)printf("\n");
    }
}

static pv_record *shell_find(pv_vault *const vault, const char *const query)
{
    size_t matches = 0U;
    pv_record *const record = pv_model_find(vault, query, &matches);
    return matches == 1U ? record : NULL;
}

static void shell_show(const pv_record *const record)
{
    size_t i;

    (void)printf("Title: ");
    shell_print_slice(&record->title);
    (void)printf("\nUsername: ");
    shell_print_slice(&record->username);
    (void)printf("\nPassword: <secret>\nURLs:\n");
    for (i = 0U; i < record->url_count; ++i) {
        (void)printf("  - ");
        shell_print_slice(&record->urls[i]);
        (void)printf("\n");
    }
}

pv_status pv_shell_run(pv_cli_context *const context)
{
    pv_clipboard_job clipboard;
    bool clipboard_ready = false;
    pv_vault vault = { 0 };
    pv_file_header header = { 0 };
    char line[512];
    pv_status status;

    if (context == NULL || !isatty(STDIN_FILENO)) {
        return PV_ERR_USAGE;
    }
    status = pv_clipboard_prepare(&clipboard, context->config.clipboard_ttl);
    if (status == PV_OK) {
        clipboard_ready = true;
    }
    {
        pv_buffer password = { 0 };
        status = pv_secure_read_secret("Master password: ", &password, false);
        if (status == PV_OK) {
            status = pv_store_open_password_consume(
                context->config.vault_path,
                &password,
                &vault,
                &header
            );
        }
        pv_buffer_secure_free(&password);
    }
    if (status != PV_OK) {
        if (clipboard_ready) pv_clipboard_cancel(&clipboard);
        return status;
    }
    (void)printf("PVault session open; idle timeout %u seconds. Type help.\n", context->config.session_ttl);
    for (;;) {
        struct pollfd item = { .fd = STDIN_FILENO, .events = POLLIN, .revents = 0 };
        int ready;
        char *command;
        char *argument;

        (void)printf("pvault> ");
        (void)fflush(stdout);
        do {
            ready = poll(&item, 1U, (int)context->config.session_ttl * 1000);
        } while (ready < 0 && errno == EINTR);
        if (ready == 0) {
            (void)printf("\nSession locked after inactivity.\n");
            status = PV_OK;
            break;
        }
        if (ready < 0 || fgets(line, sizeof(line), stdin) == NULL) {
            status = ready < 0 ? PV_ERR_IO : PV_OK;
            break;
        }
        line[strcspn(line, "\r\n")] = '\0';
        command = line;
        while (*command == ' ' || *command == '\t') ++command;
        argument = command;
        while (*argument != '\0' && *argument != ' ' && *argument != '\t') ++argument;
        if (*argument != '\0') {
            *argument++ = '\0';
            while (*argument == ' ' || *argument == '\t') ++argument;
        }
        if (strcmp(command, "quit") == 0 || strcmp(command, "lock") == 0) {
            status = PV_OK;
            break;
        }
        if (strcmp(command, "help") == 0) {
            (void)printf("Commands: list, show QUERY, copy QUERY, lock, quit\n");
        } else if (strcmp(command, "list") == 0) {
            shell_list(&vault);
        } else if (strcmp(command, "show") == 0 && *argument != '\0') {
            pv_record *const record = shell_find(&vault, argument);
            if (record == NULL) (void)printf("No unique match.\n");
            else shell_show(record);
        } else if (strcmp(command, "copy") == 0 && *argument != '\0') {
            pv_record *const record = shell_find(&vault, argument);
            if (!clipboard_ready) {
                (void)printf("Clipboard backend unavailable for this session.\n");
            } else if (record == NULL || record->password.len == 0U) {
                (void)printf("No unique match or no password.\n");
            } else {
                status = pv_clipboard_send(&clipboard, record->password.data, record->password.len);
                clipboard_ready = false;
                if (status == PV_OK) {
                    (void)printf("Password queued to the clipboard owner; session locks now.\n");
                }
                break;
            }
        } else if (*command != '\0') {
            (void)printf("Unknown command. Type help.\n");
        }
        sodium_memzero(line, sizeof(line));
    }
    if (clipboard_ready) pv_clipboard_cancel(&clipboard);
    sodium_memzero(line, sizeof(line));
    pv_model_destroy(&vault);
    sodium_memzero(&header, sizeof(header));
    return status;
}
