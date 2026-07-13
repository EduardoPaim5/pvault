#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

extern char **environ;

static bool home_path(char path[PATH_MAX], const char *const name)
{
    const char *const home = getenv("HOME");
    int written;

    if (home == NULL || home[0] != '/') return false;
    written = snprintf(path, PATH_MAX, "%s/%s", home, name);
    return written > 0 && written < PATH_MAX;
}

static void read_mode(char mode[32])
{
    char path[PATH_MAX];
    FILE *stream;

    (void)strcpy(mode, "valid");
    if (!home_path(path, "fake-rofi.mode")) return;
    stream = fopen(path, "r");
    if (stream == NULL) return;
    if (fgets(mode, 32, stream) != NULL) mode[strcspn(mode, "\r\n")] = '\0';
    (void)fclose(stream);
}

static bool write_state(const char *const name, const char *const text, const bool append)
{
    char path[PATH_MAX];
    FILE *stream;
    bool ok;

    if (!home_path(path, name)) return false;
    stream = fopen(path, append ? "a" : "w");
    if (stream == NULL) return false;
    ok = fputs(text, stream) >= 0;
    if (fclose(stream) != 0) ok = false;
    return ok;
}

static bool environment_allowed(void)
{
    static const char *const allowed[] = {
        "PATH",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
        "HOME",
        "XAUTHORITY",
        "XDG_CONFIG_HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE"
    };
    const char *const path = getenv("PATH");
    size_t entry;

    if (path == NULL || strcmp(path, "/usr/bin:/bin") != 0) {
        return false;
    }
    for (entry = 0U; environ != NULL && environ[entry] != NULL; ++entry) {
        const char *const equals = strchr(environ[entry], '=');
        size_t index;
        bool found = false;

        if (equals == NULL) return false;
        if (strncmp(environ[entry], "PATH=", 5U) == 0 &&
            strcmp(environ[entry], "PATH=/usr/bin:/bin") != 0) {
            return false;
        }
        for (index = 0U; index < sizeof(allowed) / sizeof(allowed[0]); ++index) {
            const size_t length = strlen(allowed[index]);

            if ((size_t)(equals - environ[entry]) == length &&
                strncmp(environ[entry], allowed[index], length) == 0) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

static bool signals_are_normalized(void)
{
    static const int checked[] = {
        SIGINT,
        SIGTERM,
        SIGHUP,
        SIGQUIT,
        SIGTSTP,
        SIGPIPE,
        SIGCHLD
    };
    sigset_t blocked;
    size_t index;

    if (sigprocmask(SIG_SETMASK, NULL, &blocked) != 0) return false;
    for (index = 0U; index < sizeof(checked) / sizeof(checked[0]); ++index) {
        struct sigaction action;

        if (sigismember(&blocked, checked[index]) != 0 ||
            sigaction(checked[index], NULL, &action) != 0 ||
            action.sa_handler != SIG_DFL) {
            return false;
        }
    }
    return true;
}

static bool inherited_fds_are_closed(void)
{
    int fd;

    for (fd = 3; fd < 4096; ++fd) {
        errno = 0;
        if (fcntl(fd, F_GETFD) >= 0 || errno != EBADF) return false;
    }
    return true;
}

static bool selection_line_valid(const char *const line, const size_t length)
{
    char expected[2048];
    char path[PATH_MAX];
    FILE *stream;
    const char *tab;
    size_t index;

    if (length < 19U || line[length - 1U] != '\n') return false;
    if (!home_path(path, "fake-rofi.expected-title")) return false;
    stream = fopen(path, "r");
    if (stream == NULL || fgets(expected, sizeof(expected), stream) == NULL) {
        if (stream != NULL) (void)fclose(stream);
        return false;
    }
    (void)fclose(stream);
    expected[strcspn(expected, "\r\n")] = '\0';
    tab = strchr(line, '\t');
    if (tab == NULL || strchr(tab + 1, '\t') != NULL ||
        (size_t)(line + length - 1U - (tab + 1)) != 16U ||
        (size_t)(tab - line) != strlen(expected) ||
        memcmp(line, expected, strlen(expected)) != 0) {
        return false;
    }
    for (index = 0U; line + index < tab; ++index) {
        const unsigned char byte = (unsigned char)line[index];

        if (byte < 0x20U || byte == 0x7fU) return false;
    }
    for (index = 0U; index < 16U; ++index) {
        if (!isxdigit((unsigned char)tab[1U + index])) return false;
    }
    return tab[17] == '\n';
}

int main(const int argc, char **const argv)
{
    char *line = NULL;
    char *extra = NULL;
    size_t capacity = 0U;
    size_t extra_capacity = 0U;
    ssize_t length;
    ssize_t extra_length;
    char mode[32];
    bool valid;

    if (argc != 5 || argv == NULL || strcmp(argv[0], "rofi") != 0 ||
        strcmp(argv[1], "-dmenu") != 0 || strcmp(argv[2], "-i") != 0 ||
        strcmp(argv[3], "-p") != 0 || strcmp(argv[4], "PVault") != 0) {
        (void)fprintf(stderr, "fake-rofi: argv contract failed\n");
        return 126;
    }
    if (!environment_allowed()) {
        (void)fprintf(stderr, "fake-rofi: environment contract failed\n");
        return 126;
    }
    if (!signals_are_normalized()) {
        (void)fprintf(stderr, "fake-rofi: signal contract failed\n");
        return 126;
    }
    if (!inherited_fds_are_closed()) {
        (void)fprintf(stderr, "fake-rofi: descriptor contract failed\n");
        return 126;
    }
    read_mode(mode);
    if (strcmp(mode, "ignore-term") == 0) {
        struct sigaction ignored;
        char pid_text[32];

        memset(&ignored, 0, sizeof(ignored));
        ignored.sa_handler = SIG_IGN;
        if (sigemptyset(&ignored.sa_mask) != 0 ||
            sigaction(SIGTERM, &ignored, NULL) != 0 ||
            snprintf(pid_text, sizeof(pid_text), "%ld\n", (long)getpid()) < 1 ||
            !write_state("fake-rofi.pid", pid_text, false) ||
            close(STDIN_FILENO) != 0) {
            return 126;
        }
        for (;;) pause();
    }
    length = getline(&line, &capacity, stdin);
    extra_length = getline(&extra, &extra_capacity, stdin);
    valid = length > 0 && selection_line_valid(line, (size_t)length) &&
        extra_length < 0 && feof(stdin);
    if (!valid) {
        const char *const tab = line == NULL ? NULL : strchr(line, '\t');
        const long tab_offset = tab == NULL ? -1L : (long)(tab - line);

        (void)fprintf(
            stderr,
            "fake-rofi: selection framing failed (length=%ld tab=%ld extra=%ld eof=%d)\n",
            (long)length,
            tab_offset,
            (long)extra_length,
            feof(stdin) != 0
        );
    }
    if (valid) {
        const char *const tab = strchr(line, '\t');
        char token_line[18];

        if (tab == NULL) {
            valid = false;
        } else {
            (void)memcpy(token_line, tab + 1, 16U);
            token_line[16] = '\n';
            token_line[17] = '\0';
            valid = write_state("fake-rofi.tokens", token_line, true);
        }
    }
    if (valid && strcmp(mode, "valid") == 0) {
        valid = fwrite(line, 1U, (size_t)length, stdout) == (size_t)length;
    } else if (valid && strcmp(mode, "unknown") == 0) {
        char *const tab = strchr(line, '\t');

        if (tab == NULL) {
            valid = false;
        } else {
            tab[1] = tab[1] == '0' ? '1' : '0';
            valid = fwrite(line, 1U, (size_t)length, stdout) == (size_t)length;
        }
    } else if (valid && strcmp(mode, "extra-tab") == 0) {
        valid = fputs("title\textra\t0000000000000000\n", stdout) >= 0;
    } else if (valid && strcmp(mode, "truncated") == 0) {
        valid = fputs("title\t1234\n", stdout) >= 0;
    } else if (valid) {
        valid = false;
    }
    free(extra);
    free(line);
    return valid && fflush(stdout) == 0 ? 0 : 126;
}
