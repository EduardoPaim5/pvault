#ifndef PVAULT_CLI_H
#define PVAULT_CLI_H

#include "clipboard.h"
#include "pvault_internal.h"

typedef struct pv_cli_context {
    pv_config config;
    const char *program_name;
} pv_cli_context;

pv_status pv_cli_run(pv_cli_context *context, int argc, char **argv);
pv_status pv_shell_run(pv_cli_context *context);

pv_status pv_tty_read_line(const char *prompt, size_t maximum, bool allow_empty, pv_buffer *output);
pv_status pv_tty_confirm(const char *prompt, bool *confirmed);
pv_status pv_tty_read_unsigned(const char *prompt, unsigned maximum, unsigned default_value, unsigned *value);

pv_status pv_ui_pick_internal(pv_vault *vault, pv_record **selected);

#endif
