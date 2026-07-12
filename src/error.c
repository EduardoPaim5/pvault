#include "pvault_internal.h"

const char *pv_status_string(const pv_status status)
{
    switch (status) {
    case PV_OK:
        return "success";
    case PV_ERR_USAGE:
        return "invalid usage";
    case PV_ERR_AUTH:
        return "authentication or integrity check failed";
    case PV_ERR_IO:
        return "I/O error";
    case PV_ERR_SECURE_MEMORY:
        return "secure memory unavailable";
    case PV_ERR_LOCKED:
        return "vault is locked or busy";
    case PV_ERR_EXTERNAL:
        return "external integration failed";
    case PV_ERR_FORMAT:
        return "invalid vault format";
    case PV_ERR_LIMIT:
        return "configured or format limit exceeded";
    case PV_ERR_NOT_FOUND:
        return "record not found";
    case PV_ERR_EXISTS:
        return "object already exists";
    case PV_ERR_STATE:
        return "invalid state";
    case PV_ERR_DURABILITY:
        return "update committed, but durability could not be confirmed";
    case PV_ERR_NOMEM:
        return "out of memory";
    case PV_ERR_UNSUPPORTED:
        return "unsupported or corrupted vault format version";
    }
    return "unknown error";
}

int pv_status_exit_code(const pv_status status)
{
    switch (status) {
    case PV_OK:
        return 0;
    case PV_ERR_USAGE:
        return 2;
    case PV_ERR_AUTH:
    case PV_ERR_FORMAT:
    case PV_ERR_UNSUPPORTED:
        return 3;
    case PV_ERR_IO:
    case PV_ERR_DURABILITY:
        return 4;
    case PV_ERR_SECURE_MEMORY:
    case PV_ERR_NOMEM:
    case PV_ERR_LIMIT:
        return 5;
    case PV_ERR_LOCKED:
    case PV_ERR_STATE:
        return 6;
    case PV_ERR_EXTERNAL:
        return 7;
    case PV_ERR_NOT_FOUND:
    case PV_ERR_EXISTS:
        return 1;
    }
    return 1;
}
