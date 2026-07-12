#include "pvault_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct pv_disk_file {
    uint8_t header_bytes[PV_FILE_HEADER_LEN];
    pv_file_header header;
    uint8_t *ciphertext;
    size_t ciphertext_len;
    uint8_t hash[crypto_generichash_BYTES];
} pv_disk_file;

#ifdef PVAULT_TEST_FAULT_INJECTION
typedef enum pv_store_fault_action {
    PV_STORE_FAULT_ACTION_NONE = 0,
    PV_STORE_FAULT_ACTION_FAIL,
    PV_STORE_FAULT_ACTION_SHORT_WRITE
} pv_store_fault_action;

typedef struct pv_store_fault_state {
    pv_store_fault_operation operation;
    pv_store_fault_action action;
    uint64_t trigger_call;
    int error_number;
    size_t short_write_bytes;
    uint64_t calls[PV_STORE_FAULT_OPERATION_COUNT];
    pv_store_fault_point point;
    int point_error_number;
    bool point_armed;
    bool point_fired;
    uint64_t point_hits[PV_STORE_FAULT_POINT_COUNT];
} pv_store_fault_state;

static pv_store_fault_state store_fault_state;

void pv_store_test_fault_reset(void)
{
    memset(&store_fault_state, 0, sizeof(store_fault_state));
}

void pv_store_test_fault_fail(
    const pv_store_fault_operation operation,
    const uint64_t call_number,
    const int error_number
)
{
    if (operation < PV_STORE_FAULT_OPEN || operation >= PV_STORE_FAULT_OPERATION_COUNT ||
        call_number == 0U) {
        return;
    }
    store_fault_state.operation = operation;
    store_fault_state.action = PV_STORE_FAULT_ACTION_FAIL;
    store_fault_state.trigger_call = call_number;
    store_fault_state.error_number = error_number > 0 ? error_number : EIO;
    store_fault_state.short_write_bytes = 0U;
}

void pv_store_test_fault_short_write(const uint64_t call_number, const size_t maximum_bytes)
{
    if (call_number == 0U || maximum_bytes == 0U) {
        return;
    }
    store_fault_state.operation = PV_STORE_FAULT_WRITE;
    store_fault_state.action = PV_STORE_FAULT_ACTION_SHORT_WRITE;
    store_fault_state.trigger_call = call_number;
    store_fault_state.error_number = 0;
    store_fault_state.short_write_bytes = maximum_bytes;
}

uint64_t pv_store_test_fault_call_count(const pv_store_fault_operation operation)
{
    if (operation < PV_STORE_FAULT_OPEN || operation >= PV_STORE_FAULT_OPERATION_COUNT) {
        return 0U;
    }
    return store_fault_state.calls[operation];
}

void pv_store_test_fault_point_fail(
    const pv_store_fault_point point,
    const int error_number
)
{
    if (point < PV_STORE_FAULT_POINT_ATOMIC_TEMP_OPEN ||
        point >= PV_STORE_FAULT_POINT_COUNT) {
        return;
    }
    store_fault_state.point = point;
    store_fault_state.point_error_number = error_number > 0 ? error_number : EIO;
    store_fault_state.point_armed = true;
    store_fault_state.point_fired = false;
}

uint64_t pv_store_test_fault_point_hit_count(const pv_store_fault_point point)
{
    if (point < PV_STORE_FAULT_POINT_ATOMIC_TEMP_OPEN ||
        point >= PV_STORE_FAULT_POINT_COUNT) {
        return 0U;
    }
    return store_fault_state.point_hits[point];
}

static bool store_fault_point_triggered(const pv_store_fault_point point)
{
    ++store_fault_state.point_hits[point];
    if (!store_fault_state.point_armed || store_fault_state.point_fired ||
        store_fault_state.point != point) {
        return false;
    }
    store_fault_state.point_fired = true;
    errno = store_fault_state.point_error_number;
    return true;
}

static bool store_fault_triggered(const pv_store_fault_operation operation)
{
    ++store_fault_state.calls[operation];
    return store_fault_state.action != PV_STORE_FAULT_ACTION_NONE &&
        store_fault_state.operation == operation &&
        store_fault_state.calls[operation] == store_fault_state.trigger_call;
}
#endif

static int store_open(const char *const path, const int flags, const mode_t mode)
{
#ifdef PVAULT_TEST_FAULT_INJECTION
    if (store_fault_triggered(PV_STORE_FAULT_OPEN)) {
        errno = store_fault_state.error_number;
        return -1;
    }
#endif
    return open(path, flags, mode);
}

static ssize_t store_write(const int fd, const void *const data, const size_t length)
{
#ifdef PVAULT_TEST_FAULT_INJECTION
    if (store_fault_triggered(PV_STORE_FAULT_WRITE)) {
        if (store_fault_state.action == PV_STORE_FAULT_ACTION_SHORT_WRITE) {
            size_t requested = store_fault_state.short_write_bytes;

            if (requested >= length && length > 1U) requested = length - 1U;
            if (requested > length) requested = length;
            return write(fd, data, requested);
        }
        errno = store_fault_state.error_number;
        return -1;
    }
#endif
    return write(fd, data, length);
}

static int store_fsync(const int fd)
{
#ifdef PVAULT_TEST_FAULT_INJECTION
    if (store_fault_triggered(PV_STORE_FAULT_FSYNC)) {
        errno = store_fault_state.error_number;
        return -1;
    }
#endif
    return fsync(fd);
}

static int store_rename(const char *const old_path, const char *const new_path)
{
#ifdef PVAULT_TEST_FAULT_INJECTION
    if (store_fault_triggered(PV_STORE_FAULT_RENAME)) {
        errno = store_fault_state.error_number;
        return -1;
    }
#endif
    return rename(old_path, new_path);
}

static int store_close(const int fd)
{
    const int result = close(fd);

#ifdef PVAULT_TEST_FAULT_INJECTION
    if (store_fault_triggered(PV_STORE_FAULT_CLOSE)) {
        errno = store_fault_state.error_number;
        return -1;
    }
#endif
    return result;
}

static pv_status write_all(const int fd, const void *const data, const size_t len)
{
    const uint8_t *cursor = data;
    size_t remaining = len;

    while (remaining > 0U) {
        const ssize_t written = store_write(fd, cursor, remaining);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return PV_ERR_IO;
        }
        cursor += (size_t)written;
        remaining -= (size_t)written;
    }
    return PV_OK;
}

static pv_status read_all(const int fd, void *const data, const size_t len)
{
    uint8_t *cursor = data;
    size_t remaining = len;

    while (remaining > 0U) {
        const ssize_t got = read(fd, cursor, remaining);
        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            return PV_ERR_IO;
        }
        cursor += (size_t)got;
        remaining -= (size_t)got;
    }
    return PV_OK;
}

static void disk_file_destroy(pv_disk_file *const disk)
{
    if (disk == NULL) {
        return;
    }
    free(disk->ciphertext);
    sodium_memzero(disk, sizeof(*disk));
}

static pv_status hash_disk_file(pv_disk_file *const disk)
{
    crypto_generichash_state state;

    if (crypto_generichash_init(&state, NULL, 0U, sizeof(disk->hash)) != 0 ||
        crypto_generichash_update(&state, disk->header_bytes, sizeof(disk->header_bytes)) != 0 ||
        crypto_generichash_update(&state, disk->ciphertext, disk->ciphertext_len) != 0 ||
        crypto_generichash_final(&state, disk->hash, sizeof(disk->hash)) != 0) {
        sodium_memzero(&state, sizeof(state));
        return PV_ERR_STATE;
    }
    sodium_memzero(&state, sizeof(state));
    return PV_OK;
}

static pv_status read_disk_file(const char *const path, pv_disk_file *const disk)
{
    int fd;
    struct stat st;
    uint64_t expected_size;
    pv_status status;

    memset(disk, 0, sizeof(*disk));
    fd = store_open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (fd < 0) {
        return PV_ERR_IO;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < (off_t)PV_FILE_HEADER_LEN) {
        (void)store_close(fd);
        return PV_ERR_FORMAT;
    }
    status = read_all(fd, disk->header_bytes, sizeof(disk->header_bytes));
    if (status == PV_OK) {
        status = pv_header_decode(disk->header_bytes, &disk->header);
    }
    if (status != PV_OK) {
        (void)store_close(fd);
        disk_file_destroy(disk);
        return status;
    }
    expected_size = (uint64_t)PV_FILE_HEADER_LEN + disk->header.body_ciphertext_len;
    if (expected_size > INT64_MAX || st.st_size != (off_t)expected_size) {
        (void)store_close(fd);
        disk_file_destroy(disk);
        return PV_ERR_FORMAT;
    }
    disk->ciphertext_len = (size_t)disk->header.body_ciphertext_len;
    disk->ciphertext = malloc(disk->ciphertext_len);
    if (disk->ciphertext == NULL) {
        (void)store_close(fd);
        disk_file_destroy(disk);
        return PV_ERR_NOMEM;
    }
    status = read_all(fd, disk->ciphertext, disk->ciphertext_len);
    if (status == PV_OK) {
        uint8_t extra;
        ssize_t result;
        do {
            result = read(fd, &extra, 1U);
        } while (result < 0 && errno == EINTR);
        if (result != 0) {
            status = PV_ERR_FORMAT;
        }
    }
    if (store_close(fd) != 0 && status == PV_OK) {
        status = PV_ERR_IO;
    }
    if (status == PV_OK) {
        status = hash_disk_file(disk);
    }
    if (status != PV_OK) {
        disk_file_destroy(disk);
    }
    return status;
}

static pv_status fsync_parent_path(const char *const path)
{
    char scratch[PATH_MAX];
    char *parent;
    int fd;
    pv_status status = PV_OK;

    if (path == NULL || strlen(path) >= sizeof(scratch)) return PV_ERR_LIMIT;
    (void)strcpy(scratch, path);
    parent = dirname(scratch);
    fd = store_open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (fd < 0 || store_fsync(fd) != 0) status = PV_ERR_IO;
    if (fd >= 0 && store_close(fd) != 0 && status == PV_OK) status = PV_ERR_IO;
    return status;
}

static pv_status make_directory(const char *const path)
{
    struct stat st;

    if (mkdir(path, 0700) == 0) {
        return fsync_parent_path(path);
    }
    if (errno != EEXIST || lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
        return PV_ERR_IO;
    }
    return PV_OK;
}

static pv_status make_private_directory(const char *const path)
{
    struct stat st;
    pv_status status = make_directory(path);

    if (status != PV_OK || lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) ||
        S_ISLNK(st.st_mode) || st.st_uid != geteuid()) {
        return PV_ERR_IO;
    }
    if ((st.st_mode & 0777) != 0700 && chmod(path, 0700) != 0) {
        return PV_ERR_IO;
    }
    return PV_OK;
}

static pv_status validate_parent_security(const char *const path)
{
    char scratch[PATH_MAX];
    char *parent;
    struct stat st;

    if (path == NULL || strlen(path) >= sizeof(scratch)) return PV_ERR_LIMIT;
    (void)strcpy(scratch, path);
    parent = dirname(scratch);
    if (lstat(parent, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0022) != 0) {
        return PV_ERR_IO;
    }
    return PV_OK;
}

static pv_status ensure_parent_directory(const char *const path, char *const parent, const size_t parent_len)
{
    char scratch[PATH_MAX];
    char current[PATH_MAX];
    char *cursor;
    char *component;

    if (path == NULL || path[0] != '/' || strlen(path) >= sizeof(scratch)) {
        return PV_ERR_USAGE;
    }
    (void)strcpy(scratch, path);
    cursor = strrchr(scratch, '/');
    if (cursor == NULL || cursor == scratch) {
        (void)strcpy(parent, "/");
        return PV_OK;
    }
    *cursor = '\0';
    if (strlen(scratch) >= parent_len) {
        return PV_ERR_LIMIT;
    }
    (void)strcpy(parent, scratch);
    current[0] = '/';
    current[1] = '\0';
    component = strtok(scratch + 1, "/");
    while (component != NULL) {
        const size_t used = strlen(current);
        const int written = snprintf(current + used, sizeof(current) - used, "%s%s", used > 1U ? "/" : "", component);
        pv_status status;
        if (written < 0 || (size_t)written >= sizeof(current) - used) {
            return PV_ERR_LIMIT;
        }
        status = make_directory(current);
        if (status != PV_OK) {
            return status;
        }
        component = strtok(NULL, "/");
    }
    return validate_parent_security(path);
}

static pv_status lock_vault(const char *const path, int *const lock_fd)
{
    char lock_path[PATH_MAX];
    struct stat st;
    int written;

    written = snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
    if (written < 0 || (size_t)written >= sizeof(lock_path)) {
        return PV_ERR_LIMIT;
    }
    *lock_fd = store_open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (*lock_fd < 0) {
        return PV_ERR_IO;
    }
    if (fstat(*lock_fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        st.st_nlink != 1 || fchmod(*lock_fd, 0600) != 0) {
        (void)store_close(*lock_fd);
        *lock_fd = -1;
        return PV_ERR_IO;
    }
    if (flock(*lock_fd, LOCK_EX | LOCK_NB) != 0) {
        const int saved_errno = errno;

        (void)store_close(*lock_fd);
        *lock_fd = -1;
        return saved_errno == EWOULDBLOCK || saved_errno == EAGAIN
            ? PV_ERR_LOCKED
            : PV_ERR_IO;
    }
    return PV_OK;
}

static void unlock_vault(const int lock_fd)
{
    if (lock_fd >= 0) {
        (void)flock(lock_fd, LOCK_UN);
        (void)store_close(lock_fd);
    }
}

static pv_status write_atomic(
    const char *const path,
    const uint8_t header[PV_FILE_HEADER_LEN],
    const uint8_t *const ciphertext,
    const size_t ciphertext_len
)
{
    char parent[PATH_MAX];
    char temporary[PATH_MAX];
    int fd = -1;
    int dir_fd = -1;
    unsigned attempt;
    pv_status status;

    status = ensure_parent_directory(path, parent, sizeof(parent));
    if (status != PV_OK) {
        return status;
    }
    for (attempt = 0U; attempt < 32U; ++attempt) {
        uint32_t random_suffix;
        int written;
        randombytes_buf(&random_suffix, sizeof(random_suffix));
        written = snprintf(temporary, sizeof(temporary), "%s.tmp.%08x", path, random_suffix);
        if (written < 0 || (size_t)written >= sizeof(temporary)) {
            return PV_ERR_LIMIT;
        }
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_ATOMIC_TEMP_OPEN)) {
            fd = -1;
        } else
#endif
        {
            fd = store_open(
                temporary,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                0600
            );
        }
        if (fd >= 0) {
            break;
        }
        if (errno != EEXIST) {
            return PV_ERR_IO;
        }
    }
    if (fd < 0) {
        return PV_ERR_IO;
    }
    status = PV_OK;
#ifdef PVAULT_TEST_FAULT_INJECTION
    if (store_fault_point_triggered(PV_STORE_FAULT_POINT_ATOMIC_HEADER_WRITE)) {
        status = PV_ERR_IO;
    } else
#endif
    {
        status = write_all(fd, header, PV_FILE_HEADER_LEN);
    }
    if (status == PV_OK) {
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_ATOMIC_BODY_WRITE)) {
            status = PV_ERR_IO;
        } else
#endif
        {
            status = write_all(fd, ciphertext, ciphertext_len);
        }
    }
    if (status == PV_OK) {
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_ATOMIC_TEMP_FSYNC)) {
            status = PV_ERR_IO;
        } else
#endif
        if (store_fsync(fd) != 0) {
            status = PV_ERR_IO;
        }
    }
    {
        int close_result = store_close(fd);

        if (status == PV_OK) {
#ifdef PVAULT_TEST_FAULT_INJECTION
            if (store_fault_point_triggered(PV_STORE_FAULT_POINT_ATOMIC_TEMP_CLOSE)) {
                close_result = -1;
            }
#endif
            if (close_result != 0) status = PV_ERR_IO;
        }
    }
    if (status == PV_OK) {
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_ATOMIC_RENAME)) {
            status = PV_ERR_IO;
        } else
#endif
        if (store_rename(temporary, path) != 0) {
            status = PV_ERR_IO;
        }
    }
    if (status == PV_OK) {
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_ATOMIC_DIR_OPEN)) {
            dir_fd = -1;
        } else
#endif
        {
            dir_fd = store_open(
                parent,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
                0
            );
        }
        if (dir_fd < 0) {
            status = PV_ERR_DURABILITY;
        } else {
#ifdef PVAULT_TEST_FAULT_INJECTION
            if (store_fault_point_triggered(PV_STORE_FAULT_POINT_ATOMIC_DIR_FSYNC)) {
                status = PV_ERR_DURABILITY;
            } else
#endif
            if (store_fsync(dir_fd) != 0) {
                status = PV_ERR_DURABILITY;
            }
        }
    }
    if (dir_fd >= 0) {
        (void)store_close(dir_fd);
    }
    if (status != PV_OK) {
        (void)unlink(temporary);
    }
    return status;
}

static pv_status copy_file_exclusive(const char *const source, const char *const destination)
{
    int input = -1;
    int output = -1;
    uint8_t buffer[65536];
    pv_status status = PV_OK;

    status = validate_parent_security(destination);
    if (status != PV_OK) return status;
    input = store_open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (input < 0) {
        return PV_ERR_IO;
    }
#ifdef PVAULT_TEST_FAULT_INJECTION
    if (store_fault_point_triggered(PV_STORE_FAULT_POINT_COPY_DEST_OPEN)) {
        output = -1;
    } else
#endif
    {
        output = store_open(
            destination,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600
        );
    }
    if (output < 0) {
        const int saved_errno = errno;

        (void)store_close(input);
        return saved_errno == EEXIST ? PV_ERR_EXISTS : PV_ERR_IO;
    }
    for (;;) {
        ssize_t got;
        do {
            got = read(input, buffer, sizeof(buffer));
        } while (got < 0 && errno == EINTR);
        if (got < 0) {
            status = PV_ERR_IO;
            break;
        }
        if (got == 0) {
            break;
        }
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_COPY_WRITE)) {
            status = PV_ERR_IO;
        } else
#endif
        {
            status = write_all(output, buffer, (size_t)got);
        }
        if (status != PV_OK) {
            break;
        }
    }
    if (status == PV_OK) {
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_COPY_FSYNC)) {
            status = PV_ERR_IO;
        } else
#endif
        if (store_fsync(output) != 0) {
            status = PV_ERR_IO;
        }
    }
    if (store_close(input) != 0 && status == PV_OK) {
        status = PV_ERR_IO;
    }
    if (store_close(output) != 0 && status == PV_OK) {
        status = PV_ERR_IO;
    }
    if (status == PV_OK) {
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_COPY_PARENT_FSYNC)) {
            status = PV_ERR_IO;
        } else
#endif
        {
            status = fsync_parent_path(destination);
        }
    }
    sodium_memzero(buffer, sizeof(buffer));
    if (status != PV_OK) {
        (void)unlink(destination);
        (void)fsync_parent_path(destination);
    }
    return status;
}

static pv_status write_snapshot_exclusive(
    const char *const destination,
    const uint8_t header[PV_FILE_HEADER_LEN],
    const uint8_t *const ciphertext,
    const size_t ciphertext_len
)
{
    int fd;
    pv_status status = validate_parent_security(destination);

    if (status != PV_OK) return status;
#ifdef PVAULT_TEST_FAULT_INJECTION
    if (store_fault_point_triggered(PV_STORE_FAULT_POINT_SNAPSHOT_OPEN)) {
        fd = -1;
    } else
#endif
    {
        fd = store_open(
            destination,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600
        );
    }
    if (fd < 0) return errno == EEXIST ? PV_ERR_EXISTS : PV_ERR_IO;
    status = PV_OK;
#ifdef PVAULT_TEST_FAULT_INJECTION
    if (store_fault_point_triggered(PV_STORE_FAULT_POINT_SNAPSHOT_WRITE)) {
        status = PV_ERR_IO;
    } else
#endif
    {
        status = write_all(fd, header, PV_FILE_HEADER_LEN);
    }
    if (status == PV_OK) status = write_all(fd, ciphertext, ciphertext_len);
    if (status == PV_OK) {
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_SNAPSHOT_FSYNC)) {
            status = PV_ERR_IO;
        } else
#endif
        if (store_fsync(fd) != 0) {
            status = PV_ERR_IO;
        }
    }
    if (store_close(fd) != 0 && status == PV_OK) status = PV_ERR_IO;
    if (status == PV_OK) {
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_SNAPSHOT_PARENT_FSYNC)) {
            status = PV_ERR_IO;
        } else
#endif
        {
            status = fsync_parent_path(destination);
        }
    }
    if (status != PV_OK) {
        (void)unlink(destination);
        (void)fsync_parent_path(destination);
    }
    return status;
}

static int compare_names(const void *const left, const void *const right)
{
    const char *const *a = left;
    const char *const *b = right;
    return strcmp(*a, *b);
}

static void prune_backups(const char *const directory, const unsigned retention)
{
    DIR *dir;
    struct dirent *entry;
    char **names = NULL;
    size_t count = 0U;
    size_t capacity = 0U;
    size_t i;
    bool complete = true;

    dir = opendir(directory);
    if (dir == NULL) {
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        char *copy;
        char **grown;
        const size_t name_len = strlen(entry->d_name);

        if (entry->d_name[0] == '.' || name_len < 5U ||
            strcmp(entry->d_name + name_len - 5U, ".pvlt") != 0) {
            continue;
        }
        if (count == capacity) {
            const size_t next = capacity == 0U ? 32U : capacity * 2U;
            grown = realloc(names, next * sizeof(*names));
            if (grown == NULL) {
                complete = false;
                break;
            }
            names = grown;
            capacity = next;
        }
        copy = strdup(entry->d_name);
        if (copy == NULL) {
            complete = false;
            break;
        }
        names[count++] = copy;
    }
    (void)closedir(dir);
    if (!complete) {
        for (i = 0U; i < count; ++i) free(names[i]);
        free(names);
        return;
    }
    if (count > 1U) {
        qsort(names, count, sizeof(*names), compare_names);
    }
    for (i = 0U; i + retention < count; ++i) {
        char path[PATH_MAX];
        const int written = snprintf(path, sizeof(path), "%s/%s", directory, names[i]);
        if (written > 0 && (size_t)written < sizeof(path)) {
            (void)unlink(path);
        }
    }
    for (i = 0U; i < count; ++i) {
        free(names[i]);
    }
    free(names);
}

static pv_status automatic_backup(
    const pv_vault *const vault,
    const pv_disk_file *const snapshot,
    const unsigned retention
)
{
    char path_copy[PATH_MAX];
    char directory[PATH_MAX];
    char backup_path[PATH_MAX];
    char *parent;
    int written;
    pv_status status;

    (void)strcpy(path_copy, vault->path);
    parent = dirname(path_copy);
    written = snprintf(directory, sizeof(directory), "%s/backups", parent);
    if (written < 0 || (size_t)written >= sizeof(directory)) {
        return PV_ERR_LIMIT;
    }
    status = make_private_directory(directory);
    if (status != PV_OK) {
        return status;
    }
    written = snprintf(
        backup_path,
        sizeof(backup_path),
        "%s/%020lld-%020llu.pvlt",
        directory,
        (long long)pv_now_ms(),
        (unsigned long long)vault->generation
    );
    if (written < 0 || (size_t)written >= sizeof(backup_path)) {
        return PV_ERR_LIMIT;
    }
    status = write_snapshot_exclusive(
        backup_path,
        snapshot->header_bytes,
        snapshot->ciphertext,
        snapshot->ciphertext_len
    );
    if (status == PV_OK) {
        prune_backups(directory, retention);
    }
    return status;
}

static pv_status save_locked(pv_vault *const vault, pv_file_header *const header, const unsigned retention)
{
    pv_buffer encoded = { 0 };
    pv_buffer ciphertext = { 0 };
    uint8_t header_bytes[PV_FILE_HEADER_LEN];
    pv_disk_file current;
    pv_status status;
    bool committed = false;
    bool commit_warning = false;
    bool verified = false;
    bool current_loaded = false;
    const bool exists = access(vault->path, F_OK) == 0;

    if (vault->generation == UINT64_MAX) {
        return PV_ERR_LIMIT;
    }

    if (exists) {
        status = read_disk_file(vault->path, &current);
        if (status != PV_OK) {
            return status;
        }
        current_loaded = true;
        if (sodium_memcmp(current.hash, vault->source_hash, sizeof(current.hash)) != 0 ||
            sodium_memcmp(current.header.vault_id, vault->vault_id, PV_VAULT_ID_BYTES) != 0) {
            disk_file_destroy(&current);
            return PV_ERR_LOCKED;
        }
    }
    ++vault->generation;
    vault->updated_ms = pv_now_ms();
    status = pv_cbor_encode(vault, &encoded);
    if (status == PV_OK) {
        status = pv_crypto_encrypt_body(header, vault->vmk, encoded.data, encoded.len, &ciphertext);
    }
    if (status == PV_OK) {
        status = pv_header_encode(header, header_bytes);
    }
    if (status == PV_OK && exists) {
        status = automatic_backup(vault, &current, retention);
    }
    if (status == PV_OK) {
        status = write_atomic(vault->path, header_bytes, ciphertext.data, ciphertext.len);
        if (status == PV_OK || status == PV_ERR_DURABILITY) {
            committed = true;
            commit_warning = status == PV_ERR_DURABILITY;
            status = PV_OK;
        }
    }
    if (committed) {
        pv_disk_file written;
        pv_status readback_status;

#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_SAVE_READBACK)) {
            readback_status = PV_ERR_IO;
        } else
#endif
        {
            readback_status = read_disk_file(vault->path, &written);
        }
        if (readback_status == PV_OK && written.ciphertext_len == ciphertext.len &&
            sodium_memcmp(written.header_bytes, header_bytes, sizeof(header_bytes)) == 0 &&
            sodium_memcmp(written.ciphertext, ciphertext.data, ciphertext.len) == 0) {
            memcpy(vault->source_hash, written.hash, sizeof(vault->source_hash));
            verified = true;
        } else {
            commit_warning = true;
        }
        if (readback_status == PV_OK) disk_file_destroy(&written);
    }
    if (committed && verified) {
        vault->dirty = false;
        (void)pv_arena_set_readonly(&vault->arena);
    } else if (!committed) {
        --vault->generation;
    }
    pv_buffer_secure_free(&ciphertext);
    pv_buffer_secure_free(&encoded);
    if (current_loaded) disk_file_destroy(&current);
    sodium_memzero(header_bytes, sizeof(header_bytes));
    if (committed && (commit_warning || !verified)) return PV_ERR_DURABILITY;
    return status;
}

pv_status pv_store_create(
    const char *const path,
    const uint8_t *const password,
    const size_t password_len,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    pv_vault *const vault
)
{
    pv_file_header header;
    int lock_fd = -1;
    pv_status status;
    char parent[PATH_MAX];

    if (path == NULL || password == NULL || recovery_key == NULL || vault == NULL) {
        return PV_ERR_USAGE;
    }
    status = ensure_parent_directory(path, parent, sizeof(parent));
    if (status != PV_OK) {
        return status;
    }
    if (access(path, F_OK) == 0) {
        return PV_ERR_EXISTS;
    }
    status = lock_vault(path, &lock_fd);
    if (status != PV_OK) {
        return status;
    }
    status = pv_model_init(vault, path);
    if (status != PV_OK) {
        unlock_vault(lock_fd);
        return status;
    }
    randombytes_buf(vault->vault_id, sizeof(vault->vault_id));
    randombytes_buf(vault->device_id, sizeof(vault->device_id));
    randombytes_buf(vault->vmk, PV_WRAP_KEY_BYTES);
    vault->created_ms = pv_now_ms();
    vault->updated_ms = vault->created_ms;
    vault->generation = 0U;
    vault->dirty = true;
    sodium_memzero(&header, sizeof(header));
    memcpy(header.vault_id, vault->vault_id, sizeof(header.vault_id));
    status = pv_crypto_create_header(&header, password, password_len, recovery_key, vault->vmk);
    if (status == PV_OK) {
        status = save_locked(vault, &header, PV_DEFAULT_BACKUP_RETENTION);
    }
    sodium_memzero(&header, sizeof(header));
    unlock_vault(lock_fd);
    if (status != PV_OK && status != PV_ERR_DURABILITY) {
        pv_model_destroy(vault);
    }
    return status;
}

static pv_status open_common(
    const char *const path,
    const uint8_t *const credential,
    const size_t credential_len,
    const bool recovery,
    pv_vault *const vault,
    pv_file_header *const header
)
{
    pv_disk_file disk;
    pv_buffer plaintext = { 0 };
    uint8_t *vmk = NULL;
    pv_status status;

    if (path == NULL || credential == NULL || vault == NULL) {
        return PV_ERR_USAGE;
    }
    memset(vault, 0, sizeof(*vault));

    status = read_disk_file(path, &disk);
    if (status != PV_OK) {
        return status;
    }
    vmk = sodium_malloc(PV_WRAP_KEY_BYTES);
    if (vmk == NULL || sodium_mlock(vmk, PV_WRAP_KEY_BYTES) != 0) {
        sodium_free(vmk);
        disk_file_destroy(&disk);
        return PV_ERR_SECURE_MEMORY;
    }
    if (recovery) {
        if (credential_len != PV_RECOVERY_KEY_BYTES) {
            status = PV_ERR_AUTH;
        } else {
            status = pv_crypto_unlock_recovery(&disk.header, credential, vmk);
        }
    } else {
        status = pv_crypto_unlock_password(&disk.header, credential, credential_len, vmk);
    }
    if (status == PV_OK) {
        status = pv_crypto_decrypt_body(
            &disk.header,
            vmk,
            disk.ciphertext,
            disk.ciphertext_len,
            &plaintext
        );
    }
    if (status == PV_OK) {
        status = pv_model_init(vault, path);
    }
    if (status == PV_OK) {
        memcpy(vault->vault_id, disk.header.vault_id, PV_VAULT_ID_BYTES);
        memcpy(vault->vmk, vmk, PV_WRAP_KEY_BYTES);
        memcpy(vault->source_hash, disk.hash, sizeof(vault->source_hash));
        status = pv_cbor_decode(plaintext.data, plaintext.len, vault);
    }
    if (status == PV_OK && sodium_memcmp(vault->vault_id, disk.header.vault_id, PV_VAULT_ID_BYTES) != 0) {
        status = PV_ERR_AUTH;
    }
    if (status == PV_OK && header != NULL) {
        *header = disk.header;
    }
    if (status != PV_OK && vault->arena.base != NULL) {
        pv_model_destroy(vault);
    }
    sodium_free(vmk);
    pv_buffer_secure_free(&plaintext);
    disk_file_destroy(&disk);
    return status;
}

pv_status pv_store_open_password(
    const char *const path,
    const uint8_t *const password,
    const size_t password_len,
    pv_vault *const vault,
    pv_file_header *const header
)
{
    return open_common(path, password, password_len, false, vault, header);
}

pv_status pv_store_open_recovery(
    const char *const path,
    const uint8_t recovery_key[PV_RECOVERY_KEY_BYTES],
    pv_vault *const vault,
    pv_file_header *const header
)
{
    return open_common(path, recovery_key, PV_RECOVERY_KEY_BYTES, true, vault, header);
}

pv_status pv_store_save(pv_vault *const vault, pv_file_header *const header, const unsigned backup_retention)
{
    int lock_fd = -1;
    pv_status status;

    if (vault == NULL || header == NULL || !vault->dirty || backup_retention == 0U) {
        return vault != NULL && !vault->dirty ? PV_OK : PV_ERR_USAGE;
    }
    status = lock_vault(vault->path, &lock_fd);
    if (status != PV_OK) {
        return status;
    }
    status = save_locked(vault, header, backup_retention);
    unlock_vault(lock_fd);
    return status;
}

pv_status pv_store_backup(
    const char *const vault_path,
    const char *const output_path,
    const uint8_t expected_hash[crypto_generichash_BYTES]
)
{
    pv_disk_file disk;
    pv_status status;

    status = read_disk_file(vault_path, &disk);
    if (status != PV_OK) {
        return status;
    }
    if (expected_hash != NULL && sodium_memcmp(disk.hash, expected_hash, sizeof(disk.hash)) != 0) {
        disk_file_destroy(&disk);
        return PV_ERR_AUTH;
    }
    status = write_snapshot_exclusive(
        output_path,
        disk.header_bytes,
        disk.ciphertext,
        disk.ciphertext_len
    );
    disk_file_destroy(&disk);
    return status;
}

pv_status pv_store_restore(
    const char *const vault_path,
    const char *const backup_path,
    const uint8_t expected_hash[crypto_generichash_BYTES]
)
{
    pv_disk_file backup;
    int lock_fd = -1;
    pv_status status;

    if (vault_path == NULL || backup_path == NULL || expected_hash == NULL) {
        return PV_ERR_USAGE;
    }
    status = read_disk_file(backup_path, &backup);
    if (status != PV_OK) {
        return status;
    }
    if (sodium_memcmp(backup.hash, expected_hash, sizeof(backup.hash)) != 0) {
        disk_file_destroy(&backup);
        return PV_ERR_AUTH;
    }
    status = lock_vault(vault_path, &lock_fd);
    if (status == PV_OK) {
        if (access(vault_path, F_OK) == 0) {
            char path_copy[PATH_MAX];
            char directory[PATH_MAX];
            char pre_restore[PATH_MAX];
            char *parent;
            int written;

            (void)strcpy(path_copy, vault_path);
            parent = dirname(path_copy);
            written = snprintf(directory, sizeof(directory), "%s/backups", parent);
            if (written < 0 || (size_t)written >= sizeof(directory)) {
                status = PV_ERR_LIMIT;
            } else {
                status = make_private_directory(directory);
            }
            if (status == PV_OK) {
                uint32_t suffix;
                randombytes_buf(&suffix, sizeof(suffix));
                written = snprintf(
                    pre_restore,
                    sizeof(pre_restore),
                    "%s/pre-restore-%020lld-%08x.pvlt",
                    directory,
                    (long long)pv_now_ms(),
                    suffix
                );
                if (written < 0 || (size_t)written >= sizeof(pre_restore)) {
                    status = PV_ERR_LIMIT;
                } else {
                    status = copy_file_exclusive(vault_path, pre_restore);
                }
            }
        }
    }
    if (status == PV_OK) {
        status = write_atomic(vault_path, backup.header_bytes, backup.ciphertext, backup.ciphertext_len);
    }
    unlock_vault(lock_fd);
    disk_file_destroy(&backup);
    return status;
}

pv_status pv_store_doctor(const char *const path, char *const message, const size_t message_len)
{
    pv_disk_file disk;
    struct stat st;
    struct stat lock_st;
    char lock_path[PATH_MAX];
    int lock_length;
    bool lock_unsafe = false;
    pv_status status;

    if (path == NULL || message == NULL || message_len == 0U) {
        return PV_ERR_USAGE;
    }
    status = read_disk_file(path, &disk);
    if (status != PV_OK) {
        (void)snprintf(message, message_len, "vault structure invalid: %s", pv_status_string(status));
        return status;
    }
    lock_length = snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
    if (lock_length < 0 || (size_t)lock_length >= sizeof(lock_path)) {
        lock_unsafe = true;
    } else if (lstat(lock_path, &lock_st) != 0) {
        lock_unsafe = errno != ENOENT;
    } else {
        lock_unsafe = !S_ISREG(lock_st.st_mode) || S_ISLNK(lock_st.st_mode) ||
            lock_st.st_uid != geteuid() || lock_st.st_nlink != 1 ||
            (lock_st.st_mode & 0077) != 0;
    }
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) || S_ISLNK(st.st_mode) ||
        st.st_uid != geteuid() || st.st_nlink != 1) {
        status = PV_ERR_IO;
        (void)snprintf(message, message_len, "vault path ownership or file type is unsafe");
    } else if ((st.st_mode & 0077) != 0) {
        status = PV_ERR_IO;
        (void)snprintf(message, message_len, "vault permissions are too broad; expected 0600");
    } else if (validate_parent_security(path) != PV_OK) {
        status = PV_ERR_IO;
        (void)snprintf(message, message_len, "vault parent directory is writable by another user");
    } else if (lock_unsafe) {
        status = PV_ERR_IO;
        (void)snprintf(message, message_len, "vault lockfile ownership or permissions are unsafe");
    } else {
        (void)snprintf(
            message,
            message_len,
            "structure OK; format %u.%u; encrypted payload %zu bytes",
            disk.header.major,
            disk.header.minor,
            disk.ciphertext_len
        );
    }
    disk_file_destroy(&disk);
    return status;
}
