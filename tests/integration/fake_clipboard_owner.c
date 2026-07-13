#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define FAKE_MAX_SECRET (2U * 1024U * 1024U)

static char signal_path[PATH_MAX];

static int write_all(const int fd, const void *const data, const size_t length)
{
    const uint8_t *cursor = data;
    size_t remaining = length;

    while (remaining > 0U) {
        const ssize_t written = write(fd, cursor, remaining);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return -1;
        cursor += (size_t)written;
        remaining -= (size_t)written;
    }
    return 0;
}

static int make_path(char output[PATH_MAX], const char *const home, const char *const name)
{
    const int length = snprintf(output, PATH_MAX, "%s/%s", home, name);
    return length > 0 && (size_t)length < PATH_MAX ? 0 : -1;
}

static int write_file(const char *const path, const char *const text)
{
    const size_t length = strlen(text);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    int result;

    if (fd < 0) return -1;
    result = write_all(fd, text, length);
    if (close(fd) != 0 && result == 0) result = -1;
    return result;
}

static int append_invocation(const char *const home)
{
    char path[PATH_MAX];
    int fd;
    int result;

    if (make_path(path, home, "invocations.log") != 0) return -1;
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    result = write_all(fd, "invoked\n", sizeof("invoked\n") - 1U);
    if (close(fd) != 0 && result == 0) result = -1;
    return result;
}

static void stop_handler(const int signal_number)
{
    const char *name = "SIGNAL\n";
    size_t length = sizeof("SIGNAL\n") - 1U;
    int fd;

    if (signal_number == SIGTERM) {
        name = "SIGTERM\n";
        length = sizeof("SIGTERM\n") - 1U;
    } else if (signal_number == SIGINT) {
        name = "SIGINT\n";
        length = sizeof("SIGINT\n") - 1U;
    } else if (signal_number == SIGHUP) {
        name = "SIGHUP\n";
        length = sizeof("SIGHUP\n") - 1U;
    }
    fd = open(signal_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        (void)write_all(fd, name, length);
        (void)close(fd);
    }
    _exit(0);
}

static int install_signal_handlers(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_handler;
    if (sigemptyset(&action.sa_mask) != 0) return -1;
    return sigaction(SIGTERM, &action, NULL) == 0 &&
        sigaction(SIGINT, &action, NULL) == 0 &&
        sigaction(SIGHUP, &action, NULL) == 0 ? 0 : -1;
}

static bool signal_is_blocked(const int signal_number)
{
    sigset_t current;

    if (sigprocmask(SIG_BLOCK, NULL, &current) != 0) return true;
    return sigismember(&current, signal_number) != 0;
}

static bool sigchld_is_default(void)
{
    struct sigaction action;

    if (sigaction(SIGCHLD, NULL, &action) != 0) return false;
    return action.sa_handler == SIG_DFL;
}

static bool contains_secret(
    const void *const haystack,
    const size_t haystack_length,
    const uint8_t *const secret,
    const size_t secret_length
)
{
    return secret_length > 0U && haystack_length >= secret_length &&
        memmem(haystack, haystack_length, secret, secret_length) != NULL;
}

static bool secret_in_arguments(
    const int argc,
    char **const argv,
    const uint8_t *const secret,
    const size_t secret_length
)
{
    int index;

    for (index = 0; index < argc; ++index) {
        if (contains_secret(argv[index], strlen(argv[index]), secret, secret_length)) return true;
    }
    return false;
}

extern char **environ;

static bool secret_in_environment(const uint8_t *const secret, const size_t secret_length)
{
    size_t index;

    for (index = 0U; environ[index] != NULL; ++index) {
        if (contains_secret(environ[index], strlen(environ[index]), secret, secret_length)) return true;
    }
    return false;
}

static bool forbidden_canary_present(void)
{
    size_t index;
    static const char key[] = "FORBIDDEN_CLIPBOARD_CANARY=";

    for (index = 0U; environ[index] != NULL; ++index) {
        if (strncmp(environ[index], key, sizeof(key) - 1U) == 0) return true;
    }
    return false;
}

static bool secret_in_cmdline(const uint8_t *const secret, const size_t secret_length)
{
    uint8_t buffer[8192];
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t received;

    if (fd < 0) return true;
    do {
        received = read(fd, buffer, sizeof(buffer));
    } while (received < 0 && errno == EINTR);
    (void)close(fd);
    if (received < 0) return true;
    return contains_secret(buffer, (size_t)received, secret, secret_length);
}

static const char *argument_shape(const int argc, char **const argv)
{
    if (argc == 5 && strcmp(argv[1], "-selection") == 0 &&
        strcmp(argv[2], "clipboard") == 0 && strcmp(argv[3], "-in") == 0 &&
        strcmp(argv[4], "-quiet") == 0) {
        return "x11";
    }
    if (argc == 4 && strcmp(argv[1], "--foreground") == 0 &&
        strcmp(argv[2], "--type") == 0 &&
        strcmp(argv[3], "text/plain;charset=utf-8") == 0) {
        return "wayland";
    }
    if (argc == 4 && strcmp(argv[1], "--foreground") == 0 &&
        strcmp(argv[2], "--type") == 0 &&
        strcmp(argv[3], "application/octet-stream") == 0) {
        return "wayland-binary";
    }
    return "unexpected";
}

static int run_clear(const char *const home)
{
    char pid_path[PATH_MAX];
    char result_path[PATH_MAX];
    char ready_path[PATH_MAX];
    char started_path[PATH_MAX];
    char failed_path[PATH_MAX];
    char fail_mode_path[PATH_MAX];
    char hang_mode_path[PATH_MAX];
    char text[512];

    if (make_path(pid_path, home, "clear.pid") != 0 ||
        make_path(result_path, home, "clear-result.json") != 0 ||
        make_path(ready_path, home, "cleared.ready") != 0 ||
        make_path(started_path, home, "clear-started.ready") != 0 ||
        make_path(failed_path, home, "clear-failed.ready") != 0 ||
        make_path(fail_mode_path, home, "mode-clear-fail") != 0 ||
        make_path(hang_mode_path, home, "mode-clear-hang") != 0 ||
        make_path(signal_path, home, "clear-signal.txt") != 0) {
        return 126;
    }
    (void)snprintf(text, sizeof(text), "%ld\n", (long)getpid());
    if (write_file(pid_path, text) != 0 || append_invocation(home) != 0) {
        return 126;
    }
    (void)snprintf(
        text,
        sizeof(text),
        "{\"argument_shape\":\"wayland-clear\","
        "\"forbidden_canary_present\":%s,\"sigchld_default\":%s,"
        "\"sigterm_blocked\":%s}\n",
        forbidden_canary_present() ? "true" : "false",
        sigchld_is_default() ? "true" : "false",
        signal_is_blocked(SIGTERM) ? "true" : "false"
    );
    if (write_file(result_path, text) != 0) {
        return 126;
    }
    if (access(fail_mode_path, F_OK) == 0) {
        (void)write_file(failed_path, "yes\n");
        return 126;
    }
    if (access(hang_mode_path, F_OK) == 0) {
        if (install_signal_handlers() != 0 || write_file(started_path, "yes\n") != 0) {
            return 126;
        }
        for (;;) pause();
    }
    return write_file(ready_path, "yes\n") == 0 ? 0 : 126;
}

int main(int argc, char **argv)
{
    const char *home = getenv("HOME");
    uint8_t *secret = NULL;
    size_t used = 0U;
    uint8_t digest[crypto_hash_sha256_BYTES];
    char digest_hex[crypto_hash_sha256_BYTES * 2U + 1U];
    char owner_path[PATH_MAX];
    char supervisor_path[PATH_MAX];
    char result_path[PATH_MAX];
    char ready_path[PATH_MAX];
    char early_path[PATH_MAX];
    char no_read_mode_path[PATH_MAX];
    char partial_read_mode_path[PATH_MAX];
    char no_read_result_path[PATH_MAX];
    char partial_read_result_path[PATH_MAX];
    char text[1024];
    bool in_argv;
    bool in_environment;
    bool in_cmdline;

    if (home == NULL || home[0] != '/') {
        return 126;
    }
    if (argc == 2 && strcmp(argv[1], "--clear") == 0) {
        return run_clear(home);
    }
    if (make_path(owner_path, home, "owner.pid") != 0 ||
        make_path(supervisor_path, home, "supervisor.pid") != 0 ||
        make_path(result_path, home, "result.json") != 0 ||
        make_path(ready_path, home, "received.ready") != 0 ||
        make_path(early_path, home, "exit-after-read") != 0 ||
        make_path(no_read_mode_path, home, "mode-exit-without-read") != 0 ||
        make_path(partial_read_mode_path, home, "mode-exit-after-partial-read") != 0 ||
        make_path(no_read_result_path, home, "exited-without-read") != 0 ||
        make_path(partial_read_result_path, home, "exited-after-partial-read") != 0 ||
        make_path(signal_path, home, "signal.txt") != 0) {
        return 126;
    }
    (void)snprintf(text, sizeof(text), "%ld\n", (long)getpid());
    if (write_file(owner_path, text) != 0) return 126;
    (void)snprintf(text, sizeof(text), "%ld\n", (long)getppid());
    if (write_file(supervisor_path, text) != 0) return 126;
    if (sodium_init() < 0 || install_signal_handlers() != 0 || append_invocation(home) != 0) {
        (void)write_file(result_path, "{\"stage\":\"initialization-failed\"}\n");
        return 126;
    }

    if (access(no_read_mode_path, F_OK) == 0) {
        (void)write_file(no_read_result_path, "yes\n");
        return 0;
    }
    if (access(partial_read_mode_path, F_OK) == 0) {
        uint8_t prefix[4096];
        ssize_t received;

        do {
            received = read(STDIN_FILENO, prefix, sizeof(prefix));
        } while (received < 0 && errno == EINTR);
        sodium_memzero(prefix, sizeof(prefix));
        if (received <= 0) return 126;
        (void)write_file(partial_read_result_path, "yes\n");
        return 0;
    }

    secret = sodium_malloc(FAKE_MAX_SECRET);
    if (secret == NULL) return 126;
    while (used < FAKE_MAX_SECRET) {
        const ssize_t received = read(STDIN_FILENO, secret + used, FAKE_MAX_SECRET - used);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0) {
            sodium_free(secret);
            return 126;
        }
        if (received == 0) break;
        used += (size_t)received;
    }
    in_argv = secret_in_arguments(argc, argv, secret, used);
    in_environment = secret_in_environment(secret, used);
    in_cmdline = secret_in_cmdline(secret, used);
    if (crypto_hash_sha256(digest, secret, (unsigned long long)used) != 0) {
        sodium_free(secret);
        return 126;
    }
    sodium_bin2hex(digest_hex, sizeof(digest_hex), digest, sizeof(digest));
    sodium_memzero(digest, sizeof(digest));
    sodium_free(secret);

    (void)snprintf(
        text,
        sizeof(text),
        "{\"argument_shape\":\"%s\",\"forbidden_canary_present\":%s,"
        "\"length\":%zu,\"secret_in_argv\":%s,\"secret_in_cmdline\":%s,"
        "\"secret_in_environment\":%s,\"sigchld_default\":%s,"
        "\"sigterm_blocked\":%s,\"sha256\":\"%s\"}\n",
        argument_shape(argc, argv),
        forbidden_canary_present() ? "true" : "false",
        used,
        in_argv ? "true" : "false",
        in_cmdline ? "true" : "false",
        in_environment ? "true" : "false",
        sigchld_is_default() ? "true" : "false",
        signal_is_blocked(SIGTERM) ? "true" : "false",
        digest_hex
    );
    sodium_memzero(digest_hex, sizeof(digest_hex));
    if (write_file(result_path, text) != 0 || write_file(ready_path, "ready\n") != 0) return 126;
    sodium_memzero(text, sizeof(text));

    if (access(early_path, F_OK) == 0) {
        char exited_path[PATH_MAX];
        const struct timespec acceptance_window = {.tv_sec = 1, .tv_nsec = 0};

        (void)nanosleep(&acceptance_window, NULL);
        if (make_path(exited_path, home, "exited-early") == 0) {
            (void)write_file(exited_path, "yes\n");
        }
        return 0;
    }
    for (;;) pause();
}
