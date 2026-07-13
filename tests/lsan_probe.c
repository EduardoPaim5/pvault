#include "pvault_internal.h"

#include <stdlib.h>
#include <string.h>

static void *volatile intentional_leak;

int main(const int argc, char **const argv)
{
    void *allocation;
    bool secure_allocator = false;

    if (argc == 2 && argv != NULL && strcmp(argv[1], "secure") == 0) {
        secure_allocator = true;
    } else if (argc != 1) {
        return 2;
    }

    if (pv_global_init() != PV_OK) {
        return 3;
    }
    allocation = secure_allocator ? sodium_malloc(137U) : malloc(137U);
    if (allocation == NULL) {
        pv_global_cleanup();
        return 4;
    }
    memset(allocation, 0x5a, 137U);
    intentional_leak = allocation;
    intentional_leak = NULL;
    pv_global_cleanup();
    return intentional_leak == NULL ? 0 : 5;
}
