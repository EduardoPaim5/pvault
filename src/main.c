#include "cli.h"

#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static bool command_ignores_config(const int argc, char **const argv)
{
    int position = 1;
    const char *command;

    if (argv == NULL || argc <= position) {
        return false;
    }
    if (argc > position + 1 && strcmp(argv[position], "--vault") == 0) {
        position += 2;
    }
    if (argc <= position) {
        return false;
    }
    command = argv[position];
    if (argc == position + 2 && strcmp(argv[position + 1], "--help") == 0) {
        return true;
    }
    if ((strcmp(command, "rescue") == 0 || strcmp(command, "recovery") == 0) &&
        argc == position + 3 && strcmp(argv[position + 2], "--help") == 0) {
        return true;
    }
    return strcmp(command, "help") == 0 || strcmp(command, "-h") == 0 ||
        strcmp(command, "--help") == 0 || strcmp(command, "--version") == 0 ||
        strcmp(command, "config") == 0 || strcmp(command, "rescue") == 0 ||
        strcmp(command, "rollback") == 0;
}

static bool command_is_config_check(const int argc, char **const argv)
{
    int position = 1;

    if (argv == NULL || argc <= position) {
        return false;
    }
    if (argc > position + 1 && strcmp(argv[position], "--vault") == 0) {
        position += 2;
    }
    return argc == position + 2 && strcmp(argv[position], "config") == 0 &&
        strcmp(argv[position + 1], "check") == 0;
}

static void report_configuration_error(const pv_status status)
{
    if (status == PV_ERR_IO) {
        (void)fprintf(
            stderr,
            "pvault: configuration: inaccessible or unsafe metadata; require a regular "
            "current-user file with one link, mode 0400 or 0600, and a safe parent\n"
        );
    } else if (status == PV_ERR_FORMAT) {
        (void)fprintf(
            stderr,
            "pvault: configuration: invalid syntax, duplicate key, NUL byte, or value\n"
        );
    } else if (status == PV_ERR_LIMIT) {
        (void)fprintf(stderr, "pvault: configuration: file, line, path, or value limit exceeded\n");
    } else {
        (void)fprintf(stderr, "pvault: configuration: %s\n", pv_status_string(status));
    }
}

int main(int argc, char **argv)
{
    pv_cli_context context;
    bool configuration_error = false;
    const bool config_check = command_is_config_check(argc, argv);
    pv_status status;

    (void)umask(077);
    (void)setlocale(LC_ALL, "");
    status = pv_global_init();
    if (status != PV_OK) {
        (void)fprintf(stderr, "pvault: initialization: %s\n", pv_status_string(status));
        return pv_status_exit_code(status);
    }
    memset(&context, 0, sizeof(context));
    context.program_name = argc > 0 && argv != NULL ? argv[0] : "pvault";
    if (command_ignores_config(argc, argv)) {
        status = pv_config_defaults(&context.config);
        if (status != PV_OK) {
            memset(&context.config, 0, sizeof(context.config));
        }
        status = PV_OK;
    } else {
        status = pv_config_load(&context.config);
        configuration_error = status != PV_OK;
    }
    if (status == PV_OK) {
        status = pv_cli_run(&context, argc, argv);
    }
    if (status != PV_OK) {
        if (configuration_error || config_check) {
            report_configuration_error(status);
        } else {
            (void)fprintf(stderr, "pvault: %s\n", pv_status_string(status));
        }
    }
    pv_global_cleanup();
    return pv_status_exit_code(status);
}
