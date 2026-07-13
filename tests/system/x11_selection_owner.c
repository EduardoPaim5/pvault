#include <X11/Xatom.h>
#include <X11/Xlib.h>
#ifdef PVAULT_X11_OWNER_PID_QUERY
#include <X11/extensions/XRes.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int usage(const char *const program)
{
#ifdef PVAULT_X11_OWNER_PID_QUERY
    (void)fprintf(stderr, "Usage: %s CLIPBOARD|CLIPBOARD_MANAGER [--pid]\n", program);
#else
    (void)fprintf(stderr, "Usage: %s CLIPBOARD|CLIPBOARD_MANAGER\n", program);
#endif
    return 2;
}

#ifdef PVAULT_X11_OWNER_PID_QUERY
static int print_owner_with_pid(Display *display, Window owner)
{
    XResClientIdSpec specification;
    XResClientIdValue *identifiers = NULL;
    long identifier_count = 0L;
    pid_t owner_pid = (pid_t)-1;
    long index;
    int event_base;
    int error_base;
    int major_version;
    int minor_version;

    if (owner == None) {
        (void)printf("0 0\n");
        return 0;
    }
    if (!XResQueryExtension(display, &event_base, &error_base) ||
        !XResQueryVersion(display, &major_version, &minor_version) ||
        (major_version < 1 || (major_version == 1 && minor_version < 2))) {
        (void)fprintf(stderr, "X-Resource extension 1.2 is unavailable\n");
        return 5;
    }
    specification.client = owner;
    specification.mask = XRES_CLIENT_ID_PID_MASK;
    if (XResQueryClientIds(
            display, 1L, &specification, &identifier_count, &identifiers
        ) != Success) {
        (void)fprintf(stderr, "cannot query X11 client PID\n");
        return 5;
    }
    for (index = 0L; index < identifier_count; ++index) {
        if (XResGetClientIdType(&identifiers[index]) == XRES_CLIENT_ID_PID) {
            owner_pid = XResGetClientPid(&identifiers[index]);
            if (owner_pid > 1) {
                break;
            }
        }
    }
    XResClientIdsDestroy(identifier_count, identifiers);
    if (owner_pid <= 1) {
        (void)fprintf(stderr, "X11 selection owner has no local client PID\n");
        return 5;
    }
    (void)printf("%lu %ld\n", (unsigned long)owner, (long)owner_pid);
    return 0;
}
#endif

int main(const int argc, char **const argv)
{
    Display *display;
    Atom selection;
    Window owner;
#ifdef PVAULT_X11_OWNER_PID_QUERY
    const int pid_query = argc == 3 && argv != NULL && strcmp(argv[2], "--pid") == 0;
#endif

    if (
#ifdef PVAULT_X11_OWNER_PID_QUERY
        (argc != 2 && !pid_query) ||
#else
        argc != 2 ||
#endif
        argv == NULL ||
        (strcmp(argv[1], "CLIPBOARD") != 0 &&
         strcmp(argv[1], "CLIPBOARD_MANAGER") != 0)) {
        return usage(argc > 0 && argv != NULL ? argv[0] : "x11-selection-owner");
    }

    display = XOpenDisplay(NULL);
    if (display == NULL) {
        (void)fprintf(stderr, "cannot open X11 display\n");
        return 3;
    }
    selection = XInternAtom(display, argv[1], False);
    if (selection == None) {
        (void)XCloseDisplay(display);
        (void)fprintf(stderr, "cannot intern X11 selection atom\n");
        return 4;
    }
    owner = XGetSelectionOwner(display, selection);
#ifdef PVAULT_X11_OWNER_PID_QUERY
    if (pid_query) {
        int result = print_owner_with_pid(display, owner);

        (void)XCloseDisplay(display);
        return result;
    }
#endif
    (void)printf("%lu\n", (unsigned long)owner);
    (void)XCloseDisplay(display);
    return 0;
}
