#ifndef PVAULT_PVAULT_H
#define PVAULT_PVAULT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PVAULT_VERSION_MAJOR 0
#define PVAULT_VERSION_MINOR 1
#define PVAULT_VERSION_PATCH 0
#define PVAULT_VERSION_MATURITY "pre-alpha"

#define PV_VAULT_ID_BYTES 16U
#define PV_RECORD_ID_BYTES 16U
#define PV_DEVICE_ID_BYTES 16U
#define PV_MAX_PLAINTEXT ((size_t)2U * 1024U * 1024U)
#define PV_DEFAULT_CLIPBOARD_TTL 10U
#define PV_DEFAULT_SESSION_TTL 300U
#define PV_DEFAULT_BACKUP_RETENTION 20U

typedef enum pv_status {
    PV_OK = 0,
    PV_ERR_USAGE,
    PV_ERR_AUTH,
    PV_ERR_IO,
    PV_ERR_SECURE_MEMORY,
    PV_ERR_LOCKED,
    PV_ERR_EXTERNAL,
    PV_ERR_FORMAT,
    PV_ERR_LIMIT,
    PV_ERR_NOT_FOUND,
    PV_ERR_EXISTS,
    PV_ERR_STATE,
    PV_ERR_DURABILITY,
    PV_ERR_NOMEM,
    PV_ERR_UNSUPPORTED
} pv_status;

typedef struct pv_buffer {
    uint8_t *data;
    size_t len;
    bool secure;
} pv_buffer;

typedef struct pv_view {
    const uint8_t *data;
    size_t len;
} pv_view;

const char *pv_status_string(pv_status status);
int pv_status_exit_code(pv_status status);
pv_status pv_global_init(void);
void pv_global_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif
