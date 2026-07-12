#include "clipboard.h"
#include "pvault_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define PV_CLIP_MAX_TTL_SECONDS 86400U
#define PV_CLIP_SETUP_MAGIC UINT32_C(0x50435631)
#define PV_CLIP_SETUP_TIMEOUT_MS 5000
#define PV_CLIP_OWNER_GRACE_MS 250
#define PV_CLIP_FALLBACK_POLL_MS 100
#define PV_CLIP_DATA_FD 3
#define PV_CLIP_CONTROL_FD 4
#define PV_CLIP_SETUP_FD 5

#ifndef PV_XCLIP_PATH
#define PV_XCLIP_PATH "/usr/bin/xclip"
#endif

#ifndef PV_WL_COPY_PATH
#define PV_WL_COPY_PATH "/usr/bin/wl-copy"
#endif

enum pv_clip_message {
    PV_CLIP_MSG_START_TEXT = 1,
    PV_CLIP_MSG_READY = 2,
    PV_CLIP_MSG_DONE = 3,
    PV_CLIP_MSG_FAILED = 4,
    PV_CLIP_MSG_ACCEPTED = 5,
    PV_CLIP_MSG_START_BINARY = 6
};

enum pv_clip_backend {
    PV_CLIP_BACKEND_NONE = 0,
    PV_CLIP_BACKEND_X11,
    PV_CLIP_BACKEND_WAYLAND
};

struct pv_clip_setup_result {
    uint32_t magic;
    int32_t status;
    int64_t worker_pid;
};

static volatile sig_atomic_t pv_clip_stop_requested;

static void close_if_open(int *fd)
{
    if (fd != NULL && *fd >= 0) {
        int saved_errno = errno;
        (void)close(*fd);
        *fd = -1;
        errno = saved_errno;
    }
}

static int set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);

    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);

    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int clear_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);

    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

static int waitpid_nointr(pid_t pid, int *status, int options)
{
    pid_t result;

    do {
        result = waitpid(pid, status, options);
    } while (result < 0 && errno == EINTR);

    if (result > (pid_t)INT_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    return (int)result;
}

static int write_all(int fd, const void *buffer, size_t length)
{
    const uint8_t *cursor = buffer;

    while (length > 0U) {
        ssize_t written = write(fd, cursor, length);

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        cursor += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

static int read_all(int fd, void *buffer, size_t length)
{
    uint8_t *cursor = buffer;

    while (length > 0U) {
        ssize_t received = read(fd, cursor, length);

        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (received == 0) {
            errno = EPIPE;
            return -1;
        }
        cursor += (size_t)received;
        length -= (size_t)received;
    }
    return 0;
}

static void harden_clip_process(void)
{
    struct rlimit no_core = {0, 0};

    (void)setrlimit(RLIMIT_CORE, &no_core);
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    (void)umask(077);
}

static int normalize_child_signal_state(void)
{
    static const int reset_signals[] = {SIGTERM, SIGINT, SIGHUP, SIGCHLD};
    struct sigaction action;
    sigset_t empty;
    size_t index;

    if (sigemptyset(&empty) != 0 || sigprocmask(SIG_SETMASK, &empty, NULL) != 0) {
        return -1;
    }
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) != 0) {
        return -1;
    }
    for (index = 0U; index < sizeof(reset_signals) / sizeof(reset_signals[0]); ++index) {
        if (sigaction(reset_signals[index], &action, NULL) != 0) {
            return -1;
        }
    }
    return 0;
}

static int set_sigchld_default(struct sigaction *previous)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) != 0) {
        return -1;
    }
    return sigaction(SIGCHLD, &action, previous);
}

static void stop_handler(int signal_number)
{
    (void)signal_number;
    pv_clip_stop_requested = 1;
}

static int install_stop_handlers(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_handler;
    if (sigemptyset(&action.sa_mask) != 0) {
        return -1;
    }
    if (sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGHUP, &action, NULL) != 0) {
        return -1;
    }
    return 0;
}

static int pidfd_open_local(pid_t pid)
{
#if defined(SYS_pidfd_open)
    return (int)syscall(SYS_pidfd_open, pid, 0U);
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

static int pidfd_signal_local(int pidfd, int signal_number)
{
#if defined(SYS_pidfd_send_signal)
    return (int)syscall(SYS_pidfd_send_signal, pidfd, signal_number, NULL, 0U);
#else
    (void)pidfd;
    (void)signal_number;
    errno = ENOSYS;
    return -1;
#endif
}

static int send_control(int fd, uint8_t message)
{
    sigset_t blocked;
    sigset_t previous;
    sigset_t pending;
    bool pipe_was_pending;
    ssize_t result;
    int saved_errno;

    if (sigemptyset(&blocked) != 0 || sigaddset(&blocked, SIGPIPE) != 0 ||
        sigprocmask(SIG_BLOCK, &blocked, &previous) != 0) {
        return -1;
    }
    if (sigpending(&pending) != 0) {
        saved_errno = errno;
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        errno = saved_errno;
        return -1;
    }
    pipe_was_pending = sigismember(&pending, SIGPIPE) == 1;
    do {
        result = write(fd, &message, sizeof(message));
    } while (result < 0 && errno == EINTR);

    saved_errno = result == (ssize_t)sizeof(message) ? 0 : (result < 0 ? errno : EIO);
    if (saved_errno == EPIPE && !pipe_was_pending) {
        const struct timespec no_wait = {.tv_sec = 0, .tv_nsec = 0};
        int waited;

        do {
            waited = sigtimedwait(&blocked, NULL, &no_wait);
        } while (waited < 0 && errno == EINTR);
    }
    if (sigprocmask(SIG_SETMASK, &previous, NULL) != 0 && saved_errno == 0) {
        saved_errno = errno;
    }
    if (saved_errno != 0) {
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int receive_control(int fd, uint8_t *message)
{
    ssize_t result;

    do {
        result = recv(fd, message, sizeof(*message), 0);
    } while (result < 0 && errno == EINTR && !pv_clip_stop_requested);

    if (result == 0) {
        errno = EPIPE;
        return -1;
    }
    return result == (ssize_t)sizeof(*message) ? 0 : -1;
}

static int poll_one(int fd, short events, int timeout_ms)
{
    struct pollfd item = {
        .fd = fd,
        .events = events,
        .revents = 0
    };
    int result;

    do {
        result = poll(&item, 1U, timeout_ms);
    } while (result < 0 && errno == EINTR && !pv_clip_stop_requested);

    if (result <= 0) {
        return result;
    }
    if ((item.revents & (POLLERR | POLLNVAL)) != 0) {
        errno = EIO;
        return -1;
    }
    return (item.revents & (events | POLLHUP)) != 0 ? 1 : 0;
}

static enum pv_clip_backend choose_backend(void)
{
    const char *wayland_display = getenv("WAYLAND_DISPLAY");
    const char *x11_display = getenv("DISPLAY");

    if (wayland_display != NULL && wayland_display[0] != '\0' &&
        access(PV_WL_COPY_PATH, X_OK) == 0) {
        return PV_CLIP_BACKEND_WAYLAND;
    }
    if (x11_display != NULL && x11_display[0] != '\0' &&
        access(PV_XCLIP_PATH, X_OK) == 0) {
        return PV_CLIP_BACKEND_X11;
    }
    return PV_CLIP_BACKEND_NONE;
}

extern char **environ;

static bool env_key_is_allowed(const char *entry)
{
    static const char *const keys[] = {
        "DISPLAY=",
        "XAUTHORITY=",
        "WAYLAND_DISPLAY=",
        "XDG_RUNTIME_DIR=",
        "HOME=",
        "LANG=",
        "LC_ALL=",
        "LC_CTYPE=",
        "DBUS_SESSION_BUS_ADDRESS="
    };
    size_t index;

    for (index = 0U; index < sizeof(keys) / sizeof(keys[0]); ++index) {
        size_t length = strlen(keys[index]);

        if (strncmp(entry, keys[index], length) == 0) {
            return true;
        }
    }
    return false;
}

static size_t build_owner_environment(char **result, size_t capacity)
{
    size_t count = 0U;
    size_t index;

    if (capacity == 0U) {
        return 0U;
    }
    for (index = 0U; environ[index] != NULL && count + 1U < capacity; ++index) {
        if (env_key_is_allowed(environ[index])) {
            result[count++] = environ[index];
        }
    }
    result[count] = NULL;
    return count;
}

static void close_fds_from(unsigned int first)
{
#if defined(SYS_close_range)
    if (syscall(SYS_close_range, first, UINT_MAX, 0U) == 0) {
        return;
    }
#endif
    {
        struct rlimit limit;
        unsigned long maximum = 65536UL;
        unsigned long fd;

        if (getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY) {
            maximum = (unsigned long)limit.rlim_cur;
        }
        for (fd = (unsigned long)first; fd < maximum; ++fd) {
            (void)close((int)fd);
        }
    }
}

static int redirect_standard_fds(void)
{
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC | O_NOCTTY);

    if (null_fd < 0) {
        return -1;
    }
    if (dup2(null_fd, STDIN_FILENO) < 0 ||
        dup2(null_fd, STDOUT_FILENO) < 0 ||
        dup2(null_fd, STDERR_FILENO) < 0) {
        int saved_errno = errno;
        (void)close(null_fd);
        errno = saved_errno;
        return -1;
    }
    if (null_fd > STDERR_FILENO) {
        (void)close(null_fd);
    }
    return 0;
}

static int redirect_output_fds(void)
{
    int null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC | O_NOCTTY);

    if (null_fd < 0) {
        return -1;
    }
    if (dup2(null_fd, STDOUT_FILENO) < 0 || dup2(null_fd, STDERR_FILENO) < 0) {
        int saved_errno = errno;

        (void)close(null_fd);
        errno = saved_errno;
        return -1;
    }
    if (null_fd > STDERR_FILENO) {
        (void)close(null_fd);
    }
    return 0;
}

static int duplicate_to_known_fds(int data_fd, int control_fd, int setup_fd)
{
    int duplicate_data = -1;
    int duplicate_control = -1;
    int duplicate_setup = -1;
    int result = -1;

    duplicate_data = fcntl(data_fd, F_DUPFD_CLOEXEC, 10);
    duplicate_control = fcntl(control_fd, F_DUPFD_CLOEXEC, 10);
    duplicate_setup = fcntl(setup_fd, F_DUPFD_CLOEXEC, 10);
    if (duplicate_data < 0 || duplicate_control < 0 || duplicate_setup < 0) {
        goto cleanup;
    }
    if (dup2(duplicate_data, PV_CLIP_DATA_FD) < 0 ||
        dup2(duplicate_control, PV_CLIP_CONTROL_FD) < 0 ||
        dup2(duplicate_setup, PV_CLIP_SETUP_FD) < 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    close_if_open(&duplicate_data);
    close_if_open(&duplicate_control);
    close_if_open(&duplicate_setup);
    return result;
}

static void report_preexec_failure(int setup_fd, pv_status status)
{
    struct pv_clip_setup_result result = {
        .magic = PV_CLIP_SETUP_MAGIC,
        .status = (int32_t)status,
        .worker_pid = (int64_t)getpid()
    };

    (void)write_all(setup_fd, &result, sizeof(result));
}

static pv_status resolve_helper_path(char *path, size_t capacity)
{
    ssize_t length;
    char *slash;
    static const char helper_name[] = "pvault-clip";
    size_t directory_length;

    if (path == NULL || capacity < sizeof(helper_name)) {
        return PV_ERR_USAGE;
    }
    length = readlink("/proc/self/exe", path, capacity - 1U);
    if (length < 0 || (size_t)length >= capacity - 1U) {
        return PV_ERR_EXTERNAL;
    }
    path[(size_t)length] = '\0';
    slash = strrchr(path, '/');
    if (slash == NULL) {
        return PV_ERR_EXTERNAL;
    }
    directory_length = (size_t)(slash - path) + 1U;
    if (directory_length > capacity - sizeof(helper_name)) {
        return PV_ERR_LIMIT;
    }
    memcpy(path + directory_length, helper_name, sizeof(helper_name));
    if (access(path, X_OK) == 0) {
        return PV_OK;
    }
    if (sizeof("/usr/bin/pvault-clip") > capacity) {
        return PV_ERR_LIMIT;
    }
    memcpy(path, "/usr/bin/pvault-clip", sizeof("/usr/bin/pvault-clip"));
    return access(path, X_OK) == 0 ? PV_OK : PV_ERR_EXTERNAL;
}

static int launch_detached_helper(const char *helper_path,
                                  int data_fd,
                                  int control_fd,
                                  int setup_fd,
                                  unsigned ttl_seconds)
{
    pid_t worker = fork();

    if (worker < 0) {
        report_preexec_failure(setup_fd, PV_ERR_IO);
        return -1;
    }
    if (worker > 0) {
        return 0;
    }

    if (setsid() < 0) {
        report_preexec_failure(setup_fd, PV_ERR_IO);
        _exit(126);
    }
    harden_clip_process();
    if (duplicate_to_known_fds(data_fd, control_fd, setup_fd) != 0) {
        report_preexec_failure(setup_fd, PV_ERR_IO);
        _exit(126);
    }
    if (redirect_standard_fds() != 0) {
        report_preexec_failure(PV_CLIP_SETUP_FD, PV_ERR_IO);
        _exit(126);
    }
    close_fds_from(6U);

    {
        char ttl_buffer[16];
        char argument_program[] = "pvault-clip";
        char argument_worker[] = "--worker";
        char argument_data_fd[] = "3";
        char argument_control_fd[] = "4";
        char argument_setup_fd[] = "5";
        char *const arguments[] = {
            argument_program,
            argument_worker,
            argument_data_fd,
            argument_control_fd,
            argument_setup_fd,
            ttl_buffer,
            NULL
        };
        int written = snprintf(ttl_buffer, sizeof(ttl_buffer), "%u", ttl_seconds);

        if (written < 1 || (size_t)written >= sizeof(ttl_buffer)) {
            report_preexec_failure(PV_CLIP_SETUP_FD, PV_ERR_LIMIT);
            _exit(126);
        }
        execv(helper_path, arguments);
    }
    report_preexec_failure(PV_CLIP_SETUP_FD, PV_ERR_EXTERNAL);
    _exit(127);
}

static int parse_fd_argument(const char *text, int *result)
{
    char *end = NULL;
    unsigned long value;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > (unsigned long)INT_MAX) {
        return -1;
    }
    *result = (int)value;
    return 0;
}

static int parse_ttl_argument(const char *text, unsigned *result)
{
    char *end = NULL;
    unsigned long value;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0UL ||
        value > (unsigned long)PV_CLIP_MAX_TTL_SECONDS) {
        return -1;
    }
    *result = (unsigned)value;
    return 0;
}

static void owner_exec(enum pv_clip_backend backend,
                       int data_fd,
                       int error_fd,
                       pid_t expected_parent,
                       bool text_content)
{
    char *environment[16];
    int saved_errno;

    if (normalize_child_signal_state() != 0) {
        saved_errno = errno;
        (void)write_all(error_fd, &saved_errno, sizeof(saved_errno));
        _exit(126);
    }
    harden_clip_process();
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) {
        saved_errno = errno;
        (void)write_all(error_fd, &saved_errno, sizeof(saved_errno));
        _exit(126);
    }
    /* Close the race where the supervisor dies before PR_SET_PDEATHSIG. */
    if (getppid() != expected_parent) {
        saved_errno = ECHILD;
        (void)write_all(error_fd, &saved_errno, sizeof(saved_errno));
        _exit(126);
    }
    if (clear_nonblocking(data_fd) != 0 || dup2(data_fd, STDIN_FILENO) < 0) {
        saved_errno = errno;
        (void)write_all(error_fd, &saved_errno, sizeof(saved_errno));
        _exit(126);
    }
    if (redirect_output_fds() != 0) {
        saved_errno = errno;
        (void)write_all(error_fd, &saved_errno, sizeof(saved_errno));
        _exit(126);
    }
    (void)build_owner_environment(environment, sizeof(environment) / sizeof(environment[0]));

    if (error_fd != 6) {
        if (dup2(error_fd, 6) < 0) {
            _exit(126);
        }
        error_fd = 6;
    }
    (void)set_cloexec(error_fd);
    close_fds_from(7U);

    if (backend == PV_CLIP_BACKEND_WAYLAND) {
        char argument_program[] = "wl-copy";
        char argument_foreground[] = "--foreground";
        char argument_type[] = "--type";
        char mime_text[] = "text/plain;charset=utf-8";
        char mime_binary[] = "application/octet-stream";
        char *const arguments[] = {
            argument_program,
            argument_foreground,
            argument_type,
            text_content ? mime_text : mime_binary,
            NULL
        };
        execve(PV_WL_COPY_PATH, arguments, environment);
    } else {
        char argument_program[] = "xclip";
        char argument_selection[] = "-selection";
        char argument_clipboard[] = "clipboard";
        char argument_input[] = "-in";
        char argument_quiet[] = "-quiet";
        char *const arguments[] = {
            argument_program,
            argument_selection,
            argument_clipboard,
            argument_input,
            argument_quiet,
            NULL
        };
        execve(PV_XCLIP_PATH, arguments, environment);
    }

    saved_errno = errno;
    (void)write_all(error_fd, &saved_errno, sizeof(saved_errno));
    _exit(127);
}

static pid_t spawn_owner(
    enum pv_clip_backend backend,
    int data_fd,
    const bool text_content
)
{
    int error_pipe[2] = {-1, -1};
    pid_t owner;
    const pid_t expected_parent = getpid();
    int child_errno = 0;
    ssize_t received;

    if (pipe2(error_pipe, O_CLOEXEC) != 0) {
        return (pid_t)-1;
    }
    owner = fork();
    if (owner < 0) {
        close_if_open(&error_pipe[0]);
        close_if_open(&error_pipe[1]);
        return (pid_t)-1;
    }
    if (owner == 0) {
        (void)close(error_pipe[0]);
        owner_exec(backend, data_fd, error_pipe[1], expected_parent, text_content);
    }

    close_if_open(&error_pipe[1]);
    do {
        received = read(error_pipe[0], &child_errno, sizeof(child_errno));
    } while (received < 0 && errno == EINTR);
    close_if_open(&error_pipe[0]);
    if (received == 0) {
        return owner;
    }

    (void)waitpid_nointr(owner, NULL, 0);
    errno = received > 0 ? child_errno : EIO;
    return (pid_t)-1;
}

static bool owner_has_exited(pid_t owner)
{
    int status = 0;
    int result = waitpid_nointr(owner, &status, WNOHANG);

    return result == (int)owner || (result < 0 && errno == ECHILD);
}

static void terminate_owner(pid_t owner, int owner_pidfd)
{
    int elapsed_ms = 0;
    int kill_result;

    if (owner <= 0 || owner_has_exited(owner)) {
        return;
    }
    if (owner_pidfd >= 0) {
        if (pidfd_signal_local(owner_pidfd, SIGTERM) != 0) {
            (void)kill(owner, SIGTERM);
        }
    } else {
        (void)kill(owner, SIGTERM);
    }

    while (elapsed_ms < PV_CLIP_OWNER_GRACE_MS) {
        struct timespec pause_time = {.tv_sec = 0, .tv_nsec = 10000000L};

        if (owner_has_exited(owner)) {
            return;
        }
        (void)nanosleep(&pause_time, NULL);
        elapsed_ms += 10;
    }

    if (owner_pidfd >= 0) {
        kill_result = pidfd_signal_local(owner_pidfd, SIGKILL);
        if (kill_result != 0) {
            kill_result = kill(owner, SIGKILL);
        }
    } else {
        kill_result = kill(owner, SIGKILL);
    }
    if (kill_result != 0) {
        /* Cleanup will exit the supervisor and trigger the owner's PDEATHSIG. */
        return;
    }
    (void)waitpid_nointr(owner, NULL, 0);
}

static int wait_for_done(int control_fd, pid_t owner, int owner_pidfd)
{
    for (;;) {
        struct pollfd items[2];
        nfds_t count = 1U;
        int timeout_ms = -1;
        int result;

        items[0].fd = control_fd;
        items[0].events = POLLIN | POLLHUP;
        items[0].revents = 0;
        if (owner_pidfd >= 0) {
            items[1].fd = owner_pidfd;
            items[1].events = POLLIN;
            items[1].revents = 0;
            count = 2U;
        } else {
            timeout_ms = PV_CLIP_FALLBACK_POLL_MS;
        }

        do {
            result = poll(items, count, timeout_ms);
        } while (result < 0 && errno == EINTR && !pv_clip_stop_requested);

        if (pv_clip_stop_requested || result < 0) {
            return -1;
        }
        if (owner_pidfd < 0 && owner_has_exited(owner)) {
            errno = ECHILD;
            return -1;
        }
        if (result == 0) {
            continue;
        }
        if (owner_pidfd >= 0 && (items[1].revents & POLLIN) != 0) {
            (void)waitpid_nointr(owner, NULL, 0);
            errno = ECHILD;
            return -1;
        }
        if ((items[0].revents & POLLIN) != 0) {
            uint8_t message = 0U;

            if (receive_control(control_fd, &message) == 0 && message == PV_CLIP_MSG_DONE) {
                return 0;
            }
            errno = EPROTO;
            return -1;
        }
        if ((items[0].revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
            errno = EPIPE;
            return -1;
        }
    }
}

static int wait_for_owner_or_timeout(pid_t owner, int owner_pidfd, int timer_fd)
{
    for (;;) {
        struct pollfd items[2];
        nfds_t count = 1U;
        int timeout_ms = PV_CLIP_FALLBACK_POLL_MS;
        int result;

        items[0].fd = timer_fd;
        items[0].events = POLLIN;
        items[0].revents = 0;
        if (owner_pidfd >= 0) {
            items[1].fd = owner_pidfd;
            items[1].events = POLLIN;
            items[1].revents = 0;
            count = 2U;
            timeout_ms = -1;
        }

        do {
            result = poll(items, count, timeout_ms);
        } while (result < 0 && errno == EINTR && !pv_clip_stop_requested);

        if (pv_clip_stop_requested || result < 0) {
            return -1;
        }
        if (owner_pidfd < 0 && owner_has_exited(owner)) {
            return 0;
        }
        if (result == 0) {
            continue;
        }
        if (owner_pidfd >= 0 && (items[1].revents & POLLIN) != 0) {
            (void)waitpid_nointr(owner, NULL, 0);
            return 0;
        }
        if ((items[0].revents & POLLIN) != 0) {
            uint64_t expirations = 0U;
            ssize_t received;

            do {
                received = read(timer_fd, &expirations, sizeof(expirations));
            } while (received < 0 && errno == EINTR);
            if (received != (ssize_t)sizeof(expirations)) {
                return -1;
            }
            return 1;
        }
    }
}

static pv_status worker_loop(int data_fd,
                             int control_fd,
                             int setup_fd,
                             unsigned ttl_seconds)
{
    struct pv_clip_setup_result setup_result;
    enum pv_clip_backend backend = PV_CLIP_BACKEND_NONE;
    uint8_t message = 0U;
    bool text_content = true;
    pid_t owner = (pid_t)-1;
    int owner_pidfd = -1;
    int timer_fd = -1;
    pv_status status = PV_ERR_EXTERNAL;

    pv_clip_stop_requested = 0;
    if (normalize_child_signal_state() != 0) {
        status = PV_ERR_IO;
        goto report_setup;
    }
    harden_clip_process();
    if (set_cloexec(data_fd) != 0 || set_cloexec(control_fd) != 0 ||
        set_cloexec(setup_fd) != 0 || install_stop_handlers() != 0) {
        status = PV_ERR_IO;
        goto report_setup;
    }
    backend = choose_backend();
    if (backend == PV_CLIP_BACKEND_NONE) {
        status = PV_ERR_EXTERNAL;
        goto report_setup;
    }
    status = PV_OK;

report_setup:
    setup_result.magic = PV_CLIP_SETUP_MAGIC;
    setup_result.status = (int32_t)status;
    setup_result.worker_pid = (int64_t)getpid();
    if (write_all(setup_fd, &setup_result, sizeof(setup_result)) != 0) {
        status = PV_ERR_IO;
    }
    close_if_open(&setup_fd);
    if (status != PV_OK) {
        goto cleanup;
    }

    if (receive_control(control_fd, &message) != 0 ||
        (message != PV_CLIP_MSG_START_TEXT && message != PV_CLIP_MSG_START_BINARY) ||
        pv_clip_stop_requested) {
        status = PV_ERR_STATE;
        goto cleanup;
    }
    text_content = message == PV_CLIP_MSG_START_TEXT;
    owner = spawn_owner(backend, data_fd, text_content);
    if (owner < 0) {
        (void)send_control(control_fd, PV_CLIP_MSG_FAILED);
        status = PV_ERR_EXTERNAL;
        goto cleanup;
    }
    close_if_open(&data_fd);
    owner_pidfd = pidfd_open_local(owner);
    timer_fd = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
    if (timer_fd < 0) {
        (void)send_control(control_fd, PV_CLIP_MSG_FAILED);
        status = PV_ERR_IO;
        goto cleanup;
    }
    if (send_control(control_fd, PV_CLIP_MSG_READY) != 0) {
        status = PV_ERR_IO;
        goto cleanup;
    }
    if (wait_for_done(control_fd, owner, owner_pidfd) != 0) {
        (void)send_control(control_fd, PV_CLIP_MSG_FAILED);
        status = PV_ERR_EXTERNAL;
        goto cleanup;
    }

    {
        struct itimerspec timer = {
            .it_interval = {.tv_sec = 0, .tv_nsec = 0},
            .it_value = {.tv_sec = (time_t)ttl_seconds, .tv_nsec = 0}
        };

        if (timerfd_settime(timer_fd, 0, &timer, NULL) != 0) {
            (void)send_control(control_fd, PV_CLIP_MSG_FAILED);
            status = PV_ERR_IO;
            goto cleanup;
        }
    }
    if (pv_clip_stop_requested || owner_has_exited(owner)) {
        (void)send_control(control_fd, PV_CLIP_MSG_FAILED);
        status = PV_ERR_EXTERNAL;
        goto cleanup;
    }
    if (send_control(control_fd, PV_CLIP_MSG_ACCEPTED) != 0) {
        status = PV_ERR_IO;
        goto cleanup;
    }
    close_if_open(&control_fd);

    {
        int wait_result = wait_for_owner_or_timeout(owner, owner_pidfd, timer_fd);

        if (wait_result < 0) {
            status = PV_ERR_IO;
            goto cleanup;
        }
        if (wait_result > 0) {
            terminate_owner(owner, owner_pidfd);
            owner = (pid_t)-1;
        } else {
            owner = (pid_t)-1;
        }
    }
    status = PV_OK;

cleanup:
    if (owner > 0) {
        terminate_owner(owner, owner_pidfd);
    }
    close_if_open(&timer_fd);
    close_if_open(&owner_pidfd);
    close_if_open(&setup_fd);
    close_if_open(&control_fd);
    close_if_open(&data_fd);
    return status;
}

static pv_status wait_for_setup(int fd, struct pv_clip_setup_result *result)
{
    int ready = poll_one(fd, POLLIN, PV_CLIP_SETUP_TIMEOUT_MS);

    if (ready == 0) {
        return PV_ERR_EXTERNAL;
    }
    if (ready < 0 || read_all(fd, result, sizeof(*result)) != 0) {
        return PV_ERR_IO;
    }
    if (result->magic != PV_CLIP_SETUP_MAGIC || result->worker_pid <= 1 ||
        result->worker_pid > (int64_t)INT_MAX) {
        return PV_ERR_FORMAT;
    }
    if (result->status < (int32_t)PV_OK || result->status > (int32_t)PV_ERR_UNSUPPORTED) {
        return PV_ERR_FORMAT;
    }
    return (pv_status)result->status;
}

static pv_status wait_for_owner_ready(int control_fd)
{
    uint8_t message = 0U;
    int ready = poll_one(control_fd, POLLIN, PV_CLIP_SETUP_TIMEOUT_MS);

    if (ready == 0) {
        return PV_ERR_EXTERNAL;
    }
    if (ready < 0 || receive_control(control_fd, &message) != 0) {
        return PV_ERR_IO;
    }
    return message == PV_CLIP_MSG_READY ? PV_OK : PV_ERR_EXTERNAL;
}

static pv_status wait_for_owner_accepted(int control_fd)
{
    uint8_t message = 0U;
    int ready = poll_one(control_fd, POLLIN, PV_CLIP_SETUP_TIMEOUT_MS);

    if (ready == 0) {
        return PV_ERR_EXTERNAL;
    }
    if (ready < 0 || receive_control(control_fd, &message) != 0) {
        return PV_ERR_IO;
    }
    return message == PV_CLIP_MSG_ACCEPTED ? PV_OK : PV_ERR_EXTERNAL;
}

static pv_status write_secret(int data_fd,
                              int control_fd,
                              const uint8_t *secret,
                              size_t secret_len)
{
    sigset_t blocked;
    sigset_t previous;
    sigset_t pending;
    bool pipe_was_pending;
    size_t offset = 0U;
    pv_status status = PV_OK;

    if (sigemptyset(&blocked) != 0 || sigaddset(&blocked, SIGPIPE) != 0 ||
        sigprocmask(SIG_BLOCK, &blocked, &previous) != 0) {
        return PV_ERR_IO;
    }
    if (sigpending(&pending) != 0) {
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        return PV_ERR_IO;
    }
    pipe_was_pending = sigismember(&pending, SIGPIPE) == 1;

    while (offset < secret_len) {
        ssize_t result = write(data_fd, secret + offset, secret_len - offset);

        if (result > 0) {
            offset += (size_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd items[2] = {
                {.fd = data_fd, .events = POLLOUT, .revents = 0},
                {.fd = control_fd, .events = POLLIN | POLLHUP, .revents = 0}
            };
            int poll_result;

            do {
                poll_result = poll(items, 2U, PV_CLIP_SETUP_TIMEOUT_MS);
            } while (poll_result < 0 && errno == EINTR);
            if (poll_result <= 0 ||
                (items[1].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
                status = PV_ERR_EXTERNAL;
                break;
            }
            continue;
        }
        status = PV_ERR_EXTERNAL;
        break;
    }

    if (status != PV_OK && errno == EPIPE && !pipe_was_pending) {
        struct timespec no_wait = {.tv_sec = 0, .tv_nsec = 0};
        int waited;

        do {
            waited = sigtimedwait(&blocked, NULL, &no_wait);
        } while (waited < 0 && errno == EINTR);
    }
    if (sigprocmask(SIG_SETMASK, &previous, NULL) != 0 && status == PV_OK) {
        status = PV_ERR_IO;
    }
    return status;
}

pv_status pv_clipboard_prepare(pv_clipboard_job *job, unsigned ttl_seconds)
{
    int data_pipe[2] = {-1, -1};
    int control_pair[2] = {-1, -1};
    int setup_pipe[2] = {-1, -1};
    char helper_path[PATH_MAX];
    struct pv_clip_setup_result setup_result;
    struct sigaction previous_sigchld;
    pid_t launcher = (pid_t)-1;
    bool sigchld_overridden = false;
    pv_status status;

    if (job == NULL) {
        return PV_ERR_USAGE;
    }
    job->write_fd = -1;
    job->control_fd = -1;
    job->supervisor_fd = -1;
    job->supervisor_pid = (pid_t)-1;
    if (ttl_seconds == 0U) {
        ttl_seconds = PV_DEFAULT_CLIPBOARD_TTL;
    }
    if (ttl_seconds > PV_CLIP_MAX_TTL_SECONDS) {
        return PV_ERR_LIMIT;
    }
    status = resolve_helper_path(helper_path, sizeof(helper_path));
    if (status != PV_OK) {
        return status;
    }
    if (pipe2(data_pipe, O_CLOEXEC) != 0 ||
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control_pair) != 0 ||
        pipe2(setup_pipe, O_CLOEXEC) != 0) {
        status = PV_ERR_IO;
        goto cleanup;
    }
    if (set_nonblocking(data_pipe[1]) != 0) {
        status = PV_ERR_IO;
        goto cleanup;
    }
    if (set_sigchld_default(&previous_sigchld) != 0) {
        status = PV_ERR_IO;
        goto cleanup;
    }
    sigchld_overridden = true;

    launcher = fork();
    if (launcher < 0) {
        status = PV_ERR_IO;
        goto cleanup;
    }
    if (launcher == 0) {
        int launch_result;

        (void)close(data_pipe[1]);
        (void)close(control_pair[0]);
        (void)close(setup_pipe[0]);
        launch_result = launch_detached_helper(helper_path,
                                               data_pipe[0],
                                               control_pair[1],
                                               setup_pipe[1],
                                               ttl_seconds);
        _exit(launch_result == 0 ? 0 : 126);
    }

    close_if_open(&data_pipe[0]);
    close_if_open(&control_pair[1]);
    close_if_open(&setup_pipe[1]);
    {
        int wait_result = waitpid_nointr(launcher, NULL, 0);
        int wait_errno = errno;

        if (sigaction(SIGCHLD, &previous_sigchld, NULL) != 0) {
            sigchld_overridden = false;
            status = PV_ERR_IO;
            goto cleanup;
        }
        sigchld_overridden = false;
        if (wait_result < 0) {
            errno = wait_errno;
            status = PV_ERR_IO;
            goto cleanup;
        }
    }
    status = wait_for_setup(setup_pipe[0], &setup_result);
    if (status != PV_OK) {
        goto cleanup;
    }

    job->write_fd = data_pipe[1];
    data_pipe[1] = -1;
    job->control_fd = control_pair[0];
    control_pair[0] = -1;
    job->supervisor_pid = (pid_t)setup_result.worker_pid;
    job->supervisor_fd = pidfd_open_local(job->supervisor_pid);
    status = PV_OK;

cleanup:
    if (sigchld_overridden && sigaction(SIGCHLD, &previous_sigchld, NULL) != 0 &&
        status == PV_OK) {
        status = PV_ERR_IO;
    }
    close_if_open(&data_pipe[0]);
    close_if_open(&data_pipe[1]);
    close_if_open(&control_pair[0]);
    close_if_open(&control_pair[1]);
    close_if_open(&setup_pipe[0]);
    close_if_open(&setup_pipe[1]);
    if (status != PV_OK && job->supervisor_pid > 1) {
        pv_clipboard_cancel(job);
    }
    return status;
}

pv_status pv_clipboard_send(pv_clipboard_job *job,
                            const uint8_t *secret,
                            size_t secret_len)
{
    pv_status status;

    if (job == NULL || secret == NULL || secret_len == 0U ||
        job->write_fd < 0 || job->control_fd < 0 || job->supervisor_pid <= 1) {
        return PV_ERR_USAGE;
    }
    if (secret_len > PV_MAX_PLAINTEXT) {
        return PV_ERR_LIMIT;
    }
    if (send_control(
            job->control_fd,
            memchr(secret, '\0', secret_len) == NULL && pv_utf8_valid(secret, secret_len)
                ? PV_CLIP_MSG_START_TEXT
                : PV_CLIP_MSG_START_BINARY
        ) != 0) {
        pv_clipboard_cancel(job);
        return PV_ERR_EXTERNAL;
    }
    status = wait_for_owner_ready(job->control_fd);
    if (status != PV_OK) {
        pv_clipboard_cancel(job);
        return status;
    }
    status = write_secret(job->write_fd, job->control_fd, secret, secret_len);
    close_if_open(&job->write_fd);
    if (status != PV_OK || send_control(job->control_fd, PV_CLIP_MSG_DONE) != 0) {
        pv_clipboard_cancel(job);
        return status != PV_OK ? status : PV_ERR_EXTERNAL;
    }
    status = wait_for_owner_accepted(job->control_fd);
    if (status != PV_OK) {
        pv_clipboard_cancel(job);
        return status;
    }

    close_if_open(&job->control_fd);
    close_if_open(&job->supervisor_fd);
    job->supervisor_pid = (pid_t)-1;
    return PV_OK;
}

void pv_clipboard_cancel(pv_clipboard_job *job)
{
    if (job == NULL) {
        return;
    }
    close_if_open(&job->write_fd);
    close_if_open(&job->control_fd);
    if (job->supervisor_pid > 1) {
        /* A closed control channel wakes the worker; never signal a reusable raw PID. */
        if (job->supervisor_fd >= 0) {
            (void)pidfd_signal_local(job->supervisor_fd, SIGTERM);
        }
    }
    close_if_open(&job->supervisor_fd);
    job->supervisor_pid = (pid_t)-1;
}

int pv_clipboard_worker_main(int argc, char **argv)
{
    int data_fd = -1;
    int control_fd = -1;
    int setup_fd = -1;
    unsigned ttl_seconds = 0U;
    pv_status status;

    if (argc != 6 || argv == NULL || strcmp(argv[1], "--worker") != 0 ||
        parse_fd_argument(argv[2], &data_fd) != 0 ||
        parse_fd_argument(argv[3], &control_fd) != 0 ||
        parse_fd_argument(argv[4], &setup_fd) != 0 ||
        parse_ttl_argument(argv[5], &ttl_seconds) != 0) {
        return pv_status_exit_code(PV_ERR_USAGE);
    }
    status = worker_loop(data_fd, control_fd, setup_fd, ttl_seconds);
    return pv_status_exit_code(status);
}
