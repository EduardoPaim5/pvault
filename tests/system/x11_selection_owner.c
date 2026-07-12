#include <X11/Xatom.h>
#include <X11/Xlib.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int usage(const char *const program)
{
    (void)fprintf(stderr, "Usage: %s CLIPBOARD|CLIPBOARD_MANAGER\n", program);
    return 2;
}

int main(const int argc, char **const argv)
{
    Display *display;
    Atom selection;
    Window owner;

    if (argc != 2 || argv == NULL ||
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
    (void)printf("%lu\n", (unsigned long)owner);
    (void)XCloseDisplay(display);
    return 0;
}
