#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

int main(const int argc, char **const argv)
{
    static const int poisoned[] = {
        SIGINT,
        SIGTERM,
        SIGHUP,
        SIGQUIT,
        SIGTSTP,
        SIGPIPE,
        SIGCHLD
    };
    struct sigaction ignored;
    sigset_t blocked;
    size_t index;
    int canary;

    if (argc < 2 || argv == NULL) return 125;
    memset(&ignored, 0, sizeof(ignored));
    ignored.sa_handler = SIG_IGN;
    if (sigemptyset(&ignored.sa_mask) != 0 || sigemptyset(&blocked) != 0) return 125;
    for (index = 0U; index < sizeof(poisoned) / sizeof(poisoned[0]); ++index) {
        if (sigaction(poisoned[index], &ignored, NULL) != 0 ||
            sigaddset(&blocked, poisoned[index]) != 0) {
            return 125;
        }
    }
    if (sigprocmask(SIG_BLOCK, &blocked, NULL) != 0) return 125;
    canary = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (canary < 0 || dup2(canary, 100) < 0 || fcntl(100, F_SETFD, 0) != 0) return 125;
    if (canary != 100) (void)close(canary);
    execv(argv[1], &argv[1]);
    return 127;
}
