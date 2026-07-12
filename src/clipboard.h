#ifndef PVAULT_CLIPBOARD_H
#define PVAULT_CLIPBOARD_H

#include "pvault/pvault.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct pv_clipboard_job {
    int write_fd;
    int control_fd;
    int supervisor_fd;
    pid_t supervisor_pid;
} pv_clipboard_job;

pv_status pv_clipboard_prepare(pv_clipboard_job *job, unsigned ttl_seconds);
pv_status pv_clipboard_send(pv_clipboard_job *job, const uint8_t *secret, size_t secret_len);
void pv_clipboard_cancel(pv_clipboard_job *job);
int pv_clipboard_worker_main(int argc, char **argv);

#endif
