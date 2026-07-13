#include "clipboard.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST_SETUP_MAGIC UINT32_C(0x50435631)

struct test_setup_result {
    uint32_t magic;
    int32_t status;
    int64_t worker_pid;
};

static int read_all(int fd, void *buffer, size_t length)
{
    unsigned char *cursor = buffer;

    while (length > 0U) {
        ssize_t received = read(fd, cursor, length);

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return -1;
        }
        cursor += (size_t)received;
        length -= (size_t)received;
    }
    return 0;
}

static void close_if_open(int *fd)
{
    if (*fd >= 0) {
        (void)close(*fd);
        *fd = -1;
    }
}

static int set_policy_environment(const char *wayland_display,
                                  const char *session_type)
{
    if (setenv("DISPLAY", ":99", 1) != 0) {
        return -1;
    }
    if (wayland_display != NULL) {
        if (setenv("WAYLAND_DISPLAY", wayland_display, 1) != 0) {
            return -1;
        }
    } else if (unsetenv("WAYLAND_DISPLAY") != 0) {
        return -1;
    }
    if (session_type != NULL) {
        if (setenv("XDG_SESSION_TYPE", session_type, 1) != 0) {
            return -1;
        }
    } else if (unsetenv("XDG_SESSION_TYPE") != 0) {
        return -1;
    }
    return 0;
}

static int run_policy_case(const char *wayland_display, const char *session_type)
{
    int data_pipe[2] = {-1, -1};
    int control_pair[2] = {-1, -1};
    int setup_pipe[2] = {-1, -1};
    char data_fd[32];
    char control_fd[32];
    char setup_fd[32];
    char program[] = "pvault-clip";
    char worker[] = "--worker";
    char ttl[] = "10";
    char *arguments[7];
    struct test_setup_result setup_result = {0};
    int worker_result;
    int result = -1;

    if (set_policy_environment(wayland_display, session_type) != 0 ||
        pipe2(data_pipe, O_CLOEXEC) != 0 ||
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control_pair) != 0 ||
        pipe2(setup_pipe, O_CLOEXEC) != 0) {
        goto cleanup;
    }
    if (snprintf(data_fd, sizeof(data_fd), "%d", data_pipe[0]) < 1 ||
        snprintf(control_fd, sizeof(control_fd), "%d", control_pair[0]) < 1 ||
        snprintf(setup_fd, sizeof(setup_fd), "%d", setup_pipe[1]) < 1) {
        goto cleanup;
    }
    arguments[0] = program;
    arguments[1] = worker;
    arguments[2] = data_fd;
    arguments[3] = control_fd;
    arguments[4] = setup_fd;
    arguments[5] = ttl;
    arguments[6] = NULL;

    /* A broken policy that falls through to X11 must fail promptly, not hang
     * waiting for a control message from this negative probe. */
    close_if_open(&data_pipe[1]);
    close_if_open(&control_pair[1]);
    worker_result = pv_clipboard_worker_main(6, arguments);
    data_pipe[0] = -1;
    control_pair[0] = -1;
    setup_pipe[1] = -1;
    if (read_all(setup_pipe[0], &setup_result, sizeof(setup_result)) != 0 ||
        worker_result != 7 ||
        worker_result != pv_status_exit_code(PV_ERR_EXTERNAL) ||
        setup_result.magic != TEST_SETUP_MAGIC ||
        setup_result.status != (int32_t)PV_ERR_EXTERNAL ||
        setup_result.worker_pid != (int64_t)getpid()) {
        goto cleanup;
    }
    result = 0;

cleanup:
    close_if_open(&data_pipe[0]);
    close_if_open(&data_pipe[1]);
    close_if_open(&control_pair[0]);
    close_if_open(&control_pair[1]);
    close_if_open(&setup_pipe[0]);
    close_if_open(&setup_pipe[1]);
    return result;
}

static int run_positive_x11_case(void)
{
    int data_pipe[2] = {-1, -1};
    int control_pair[2] = {-1, -1};
    int setup_pipe[2] = {-1, -1};
    char data_fd[32];
    char control_fd[32];
    char setup_fd[32];
    char program[] = "pvault-clip";
    char worker[] = "--worker";
    char ttl[] = "10";
    char *arguments[7];
    const uint8_t start_message = 1U;
    struct test_setup_result setup_result = {0};
    int setup_read_result;
    ssize_t sent;
    int worker_result;
    int result = -1;

    if (set_policy_environment(NULL, "x11") != 0 ||
        pipe2(data_pipe, O_CLOEXEC) != 0 ||
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control_pair) != 0 ||
        pipe2(setup_pipe, O_CLOEXEC) != 0) {
        goto cleanup;
    }
    if (snprintf(data_fd, sizeof(data_fd), "%d", data_pipe[0]) < 1 ||
        snprintf(control_fd, sizeof(control_fd), "%d", control_pair[0]) < 1 ||
        snprintf(setup_fd, sizeof(setup_fd), "%d", setup_pipe[1]) < 1) {
        goto cleanup;
    }
    arguments[0] = program;
    arguments[1] = worker;
    arguments[2] = data_fd;
    arguments[3] = control_fd;
    arguments[4] = setup_fd;
    arguments[5] = ttl;
    arguments[6] = NULL;

    do {
        sent = write(control_pair[1], &start_message, sizeof(start_message));
    } while (sent < 0 && errno == EINTR);
    if (sent != (ssize_t)sizeof(start_message)) {
        goto cleanup;
    }
    worker_result = pv_clipboard_worker_main(6, arguments);
    data_pipe[0] = -1;
    control_pair[0] = -1;
    setup_pipe[1] = -1;
    setup_read_result = read_all(setup_pipe[0], &setup_result, sizeof(setup_result));
    if (setup_read_result != 0 ||
        worker_result == pv_status_exit_code(PV_OK) ||
        setup_result.magic != TEST_SETUP_MAGIC ||
        setup_result.status != (int32_t)PV_OK ||
        setup_result.worker_pid != (int64_t)getpid()) {
        goto cleanup;
    }
    result = 0;

cleanup:
    close_if_open(&data_pipe[0]);
    close_if_open(&data_pipe[1]);
    close_if_open(&control_pair[0]);
    close_if_open(&control_pair[1]);
    close_if_open(&setup_pipe[0]);
    close_if_open(&setup_pipe[1]);
    return result;
}

int main(void)
{
    if (access("/bin/true", X_OK) != 0) {
        return 2;
    }
    if (run_policy_case("wayland-policy-test", NULL) != 0) {
        return 1;
    }
    if (run_policy_case(NULL, "wayland") != 0) {
        return 1;
    }
    if (run_policy_case(NULL, NULL) != 0) {
        return 1;
    }
    if (run_positive_x11_case() != 0) {
        return 1;
    }
    return 0;
}
