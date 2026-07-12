#include "cli.h"

#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
    pv_cli_context context;
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
    status = pv_config_load(&context.config);
    if (status == PV_OK) {
        status = pv_cli_run(&context, argc, argv);
    }
    if (status != PV_OK) {
        (void)fprintf(stderr, "pvault: %s\n", pv_status_string(status));
    }
    pv_global_cleanup();
    return pv_status_exit_code(status);
}
