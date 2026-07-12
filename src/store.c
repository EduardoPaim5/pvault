#include "pvault_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0U)
#endif

typedef struct pv_disk_file {
    uint8_t header_bytes[PV_FILE_HEADER_LEN];
    pv_file_header header;
    uint8_t *ciphertext;
    size_t ciphertext_len;
    uint8_t hash[crypto_generichash_BYTES];
    struct stat snapshot_stat;
} pv_disk_file;

typedef struct pv_store_location {
    int directory_fd;
    char name[PATH_MAX];
    dev_t device;
    ino_t inode;
} pv_store_location;

typedef enum pv_private_snapshot_issue {
    PV_PRIVATE_SNAPSHOT_OK = 0,
    PV_PRIVATE_SNAPSHOT_PATH,
    PV_PRIVATE_SNAPSHOT_PARENT,
    PV_PRIVATE_SNAPSHOT_TYPE,
    PV_PRIVATE_SNAPSHOT_OWNER,
    PV_PRIVATE_SNAPSHOT_LINKS,
    PV_PRIVATE_SNAPSHOT_MODE
} pv_private_snapshot_issue;

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

static int store_openat(
    const int directory_fd,
    const char *const path,
    const int flags,
    const mode_t mode
)
{
#ifdef PVAULT_TEST_FAULT_INJECTION
    if (store_fault_triggered(PV_STORE_FAULT_OPEN)) {
        errno = store_fault_state.error_number;
        return -1;
    }
#endif
    return openat(directory_fd, path, flags, mode);
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

static int store_renameat(
    const int old_directory_fd,
    const char *const old_path,
    const int new_directory_fd,
    const char *const new_path,
    const bool no_replace
)
{
#ifdef PVAULT_TEST_FAULT_INJECTION
    if (store_fault_triggered(PV_STORE_FAULT_RENAME)) {
        errno = store_fault_state.error_number;
        return -1;
    }
#endif
#if defined(SYS_renameat2)
    {
        const int result = (int)syscall(
            SYS_renameat2,
            old_directory_fd,
            old_path,
            new_directory_fd,
            new_path,
            no_replace ? RENAME_NOREPLACE : 0U
        );

        if (result == 0 || errno != ENOSYS || no_replace) {
            return result;
        }
    }
    return renameat(old_directory_fd, old_path, new_directory_fd, new_path);
#else
    if (no_replace) {
        errno = ENOTSUP;
        return -1;
    }
    return renameat(old_directory_fd, old_path, new_directory_fd, new_path);
#endif
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

static pv_status split_parent_and_name(
    const char *const path,
    char parent[PATH_MAX],
    char name[PATH_MAX]
)
{
    const char *slash;
    const char *base;
    size_t parent_len;
    size_t name_len;

    if (path == NULL || path[0] == '\0' || strlen(path) >= PATH_MAX) {
        return PV_ERR_USAGE;
    }
    slash = strrchr(path, '/');
    if (slash == NULL) {
        base = path;
        parent[0] = '.';
        parent[1] = '\0';
    } else {
        base = slash + 1;
        parent_len = (size_t)(slash - path);
        if (parent_len == 0U) {
            parent[0] = '/';
            parent[1] = '\0';
        } else {
            if (parent_len >= PATH_MAX) {
                return PV_ERR_LIMIT;
            }
            (void)memcpy(parent, path, parent_len);
            parent[parent_len] = '\0';
        }
    }
    name_len = strlen(base);
    if (name_len == 0U || name_len >= PATH_MAX || strcmp(base, ".") == 0 ||
        strcmp(base, "..") == 0) {
        return PV_ERR_USAGE;
    }
    (void)memcpy(name, base, name_len + 1U);
    return PV_OK;
}

static pv_status path_entry_exists_at(
    const int directory_fd,
    const char *const name,
    bool *const exists
)
{
    struct stat st;

    if (directory_fd < 0 || name == NULL || exists == NULL) {
        return PV_ERR_USAGE;
    }
    if (fstatat(directory_fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        *exists = true;
        return PV_OK;
    }
    if (errno == ENOENT) {
        *exists = false;
        return PV_OK;
    }
    return PV_ERR_IO;
}

static pv_private_snapshot_issue private_snapshot_stat_issue(const struct stat *const st)
{
    const mode_t access_mode = st->st_mode & 07777;

    if (!S_ISREG(st->st_mode)) {
        return PV_PRIVATE_SNAPSHOT_TYPE;
    }
    if (st->st_uid != geteuid()) {
        return PV_PRIVATE_SNAPSHOT_OWNER;
    }
    if (st->st_nlink != 1) {
        return PV_PRIVATE_SNAPSHOT_LINKS;
    }
    if (access_mode != 0400 && access_mode != 0600) {
        return PV_PRIVATE_SNAPSHOT_MODE;
    }
    return PV_PRIVATE_SNAPSHOT_OK;
}

static pv_status open_private_parent(
    const char *const path,
    int *const parent_fd,
    char name[PATH_MAX],
    pv_private_snapshot_issue *const issue
)
{
    char parent[PATH_MAX];
    struct stat st;
    pv_status status;

    *parent_fd = -1;
    if (issue != NULL) {
        *issue = PV_PRIVATE_SNAPSHOT_PATH;
    }
    status = split_parent_and_name(path, parent, name);
    if (status != PV_OK) {
        return status;
    }
    *parent_fd = store_open(
        parent,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
        0
    );
    if (*parent_fd < 0) {
        if (issue != NULL) {
            *issue = PV_PRIVATE_SNAPSHOT_PARENT;
        }
        return PV_ERR_IO;
    }
    if (fstat(*parent_fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0022) != 0) {
        (void)store_close(*parent_fd);
        *parent_fd = -1;
        if (issue != NULL) {
            *issue = PV_PRIVATE_SNAPSHOT_PARENT;
        }
        return PV_ERR_IO;
    }
    return PV_OK;
}

static pv_status open_store_location(
    const char *const path,
    pv_store_location *const location,
    pv_private_snapshot_issue *const issue
)
{
    struct stat st;
    pv_status status;

    if (location == NULL) {
        return PV_ERR_USAGE;
    }
    memset(location, 0, sizeof(*location));
    location->directory_fd = -1;
    status = open_private_parent(path, &location->directory_fd, location->name, issue);
    if (status != PV_OK) {
        return status;
    }
    if (fstat(location->directory_fd, &st) != 0) {
        (void)store_close(location->directory_fd);
        location->directory_fd = -1;
        return PV_ERR_IO;
    }
    location->device = st.st_dev;
    location->inode = st.st_ino;
    return PV_OK;
}

static void close_store_location(pv_store_location *const location)
{
    if (location != NULL && location->directory_fd >= 0) {
        (void)store_close(location->directory_fd);
        location->directory_fd = -1;
    }
}

static pv_status revalidate_store_location(
    const char *const path,
    const pv_store_location *const held
)
{
    pv_store_location current;
    pv_status status;

    if (path == NULL || held == NULL || held->directory_fd < 0) {
        return PV_ERR_USAGE;
    }
    status = open_store_location(path, &current, NULL);
    if (status != PV_OK) {
        return status;
    }
    if (current.device != held->device || current.inode != held->inode ||
        strcmp(current.name, held->name) != 0) {
        status = PV_ERR_LOCKED;
    }
    close_store_location(&current);
    return status;
}

static pv_status open_private_snapshot_at(
    const int directory_fd,
    const char *const name,
    int *const snapshot_fd,
    struct stat *const snapshot_stat,
    pv_private_snapshot_issue *const issue
)
{
    struct stat st;
    pv_private_snapshot_issue local_issue = PV_PRIVATE_SNAPSHOT_PATH;
    pv_status status = PV_OK;

    if (directory_fd < 0 || name == NULL || snapshot_fd == NULL) {
        return PV_ERR_USAGE;
    }
    *snapshot_fd = store_openat(
        directory_fd,
        name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
        0
    );
    if (*snapshot_fd < 0 || fstat(*snapshot_fd, &st) != 0) {
        status = PV_ERR_IO;
    } else {
        local_issue = private_snapshot_stat_issue(&st);
        status = local_issue == PV_PRIVATE_SNAPSHOT_OK ? PV_OK : PV_ERR_IO;
    }
    if (status != PV_OK && *snapshot_fd >= 0) {
        (void)store_close(*snapshot_fd);
        *snapshot_fd = -1;
    } else if (status == PV_OK && snapshot_stat != NULL) {
        *snapshot_stat = st;
    }
    if (issue != NULL) {
        *issue = local_issue;
    }
    return status;
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

static pv_status read_disk_file_at(
    const int directory_fd,
    const char *const name,
    pv_disk_file *const disk
)
{
    int fd;
    struct stat st;
    uint64_t expected_size;
    pv_status status;

    memset(disk, 0, sizeof(*disk));
    status = open_private_snapshot_at(directory_fd, name, &fd, &st, NULL);
    if (status != PV_OK) {
        return status;
    }
    if (st.st_size < (off_t)PV_FILE_HEADER_LEN) {
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
    if (status == PV_OK) {
        disk->snapshot_stat = st;
    }
    if (status != PV_OK) {
        disk_file_destroy(disk);
    }
    return status;
}

static pv_status read_disk_file(const char *const path, pv_disk_file *const disk)
{
    pv_store_location location;
    pv_status status;

    status = open_store_location(path, &location, NULL);
    if (status != PV_OK) {
        return status;
    }
    status = read_disk_file_at(location.directory_fd, location.name, disk);
    if (status == PV_OK && revalidate_store_location(path, &location) != PV_OK) {
        disk_file_destroy(disk);
        status = PV_ERR_LOCKED;
    }
    close_store_location(&location);
    return status;
}

static pv_status fsync_parent_path(const char *const path)
{
    char scratch[PATH_MAX];
    char *parent;
    size_t path_len;
    int fd;
    pv_status status = PV_OK;

    if (path == NULL) return PV_ERR_LIMIT;
    path_len = strlen(path);
    if (path_len >= sizeof scratch) return PV_ERR_LIMIT;
    (void)memcpy(scratch, path, path_len + 1U);
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

static pv_status make_private_directory_at(
    const int parent_fd,
    const char *const name,
    int *const directory_fd
)
{
    struct stat st;
    bool created = false;

    if (parent_fd < 0 || name == NULL || directory_fd == NULL ||
        name[0] == '\0' || strchr(name, '/') != NULL) {
        return PV_ERR_USAGE;
    }
    *directory_fd = -1;
    if (mkdirat(parent_fd, name, 0700) == 0) {
        created = true;
    } else if (errno != EEXIST) {
        return PV_ERR_IO;
    }
    *directory_fd = store_openat(
        parent_fd,
        name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
        0
    );
    if (*directory_fd < 0 || fstat(*directory_fd, &st) != 0 ||
        !S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
        fchmod(*directory_fd, 0700) != 0 || fstat(*directory_fd, &st) != 0 ||
        (st.st_mode & 07777) != 0700) {
        if (*directory_fd >= 0) {
            (void)store_close(*directory_fd);
            *directory_fd = -1;
        }
        return PV_ERR_IO;
    }
    if (created && store_fsync(parent_fd) != 0) {
        (void)store_close(*directory_fd);
        *directory_fd = -1;
        return PV_ERR_IO;
    }
    return PV_OK;
}

static pv_status validate_parent_security(const char *const path)
{
    char name[PATH_MAX];
    int parent_fd = -1;
    pv_status status;

    status = open_private_parent(path, &parent_fd, name, NULL);
    if (status != PV_OK) {
        return status;
    }
    if (store_close(parent_fd) != 0) {
        return PV_ERR_IO;
    }
    return status;
}

static pv_status ensure_parent_directory(const char *const path, char *const parent, const size_t parent_len)
{
    char scratch[PATH_MAX];
    char current[PATH_MAX];
    char *cursor;
    char *component;
    size_t path_len;
    size_t scratch_len;

    if (path == NULL || path[0] != '/') {
        return PV_ERR_USAGE;
    }
    path_len = strlen(path);
    if (path_len >= sizeof scratch) {
        return PV_ERR_USAGE;
    }
    (void)memcpy(scratch, path, path_len + 1U);
    cursor = strrchr(scratch, '/');
    if (cursor == NULL || cursor == scratch) {
        if (parent_len < 2U) return PV_ERR_LIMIT;
        parent[0] = '/';
        parent[1] = '\0';
        return PV_OK;
    }
    *cursor = '\0';
    scratch_len = strlen(scratch);
    if (scratch_len >= parent_len) {
        return PV_ERR_LIMIT;
    }
    (void)memcpy(parent, scratch, scratch_len + 1U);
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

static pv_status lock_vault(
    const char *const path,
    pv_store_location *const location,
    int *const lock_fd
)
{
    char lock_name[PATH_MAX];
    struct stat st;
    int written;
    pv_status status;

    if (path == NULL || location == NULL || lock_fd == NULL) {
        return PV_ERR_USAGE;
    }
    *lock_fd = -1;
    status = open_store_location(path, location, NULL);
    if (status != PV_OK) {
        return status;
    }

    written = snprintf(lock_name, sizeof(lock_name), "%s.lock", location->name);
    if (written < 0 || (size_t)written >= sizeof(lock_name)) {
        close_store_location(location);
        return PV_ERR_LIMIT;
    }
    *lock_fd = store_openat(
        location->directory_fd,
        lock_name,
        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
        0600
    );
    if (*lock_fd < 0) {
        close_store_location(location);
        return PV_ERR_IO;
    }
    if (fstat(*lock_fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        st.st_nlink != 1 || fchmod(*lock_fd, 0600) != 0) {
        (void)store_close(*lock_fd);
        *lock_fd = -1;
        close_store_location(location);
        return PV_ERR_IO;
    }
    if (flock(*lock_fd, LOCK_EX | LOCK_NB) != 0) {
        const int saved_errno = errno;

        (void)store_close(*lock_fd);
        *lock_fd = -1;
        close_store_location(location);
        return saved_errno == EWOULDBLOCK || saved_errno == EAGAIN
            ? PV_ERR_LOCKED
            : PV_ERR_IO;
    }
    return PV_OK;
}

static void unlock_vault(const int lock_fd, pv_store_location *const location)
{
    if (lock_fd >= 0) {
        (void)flock(lock_fd, LOCK_UN);
        (void)store_close(lock_fd);
    }
    close_store_location(location);
}

static pv_status write_atomic_at(
    const pv_store_location *const location,
    const uint8_t header[PV_FILE_HEADER_LEN],
    const uint8_t *const ciphertext,
    const size_t ciphertext_len,
    const bool no_replace
)
{
    char temporary[PATH_MAX];
    struct stat temporary_stat;
    int fd = -1;
    unsigned attempt;
    pv_status status = PV_OK;
    bool published = false;

    if (location == NULL || location->directory_fd < 0 || header == NULL ||
        ciphertext == NULL || ciphertext_len == 0U) {
        return PV_ERR_USAGE;
    }
    for (attempt = 0U; attempt < 32U; ++attempt) {
        uint32_t random_suffix;
        int written;
        randombytes_buf(&random_suffix, sizeof(random_suffix));
        written = snprintf(
            temporary,
            sizeof(temporary),
            "%s.tmp.%08x",
            location->name,
            random_suffix
        );
        if (written < 0 || (size_t)written >= sizeof(temporary)) {
            return PV_ERR_LIMIT;
        }
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_ATOMIC_TEMP_OPEN)) {
            fd = -1;
        } else
#endif
        {
            fd = store_openat(
                location->directory_fd,
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
    if (fstat(fd, &temporary_stat) != 0 ||
        private_snapshot_stat_issue(&temporary_stat) != PV_PRIVATE_SNAPSHOT_OK) {
        (void)store_close(fd);
        (void)unlinkat(location->directory_fd, temporary, 0);
        return PV_ERR_IO;
    }
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
    if (status == PV_OK && (fstat(fd, &temporary_stat) != 0 ||
            private_snapshot_stat_issue(&temporary_stat) != PV_PRIVATE_SNAPSHOT_OK)) {
        status = PV_ERR_IO;
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
        if (store_renameat(
                location->directory_fd,
                temporary,
                location->directory_fd,
                location->name,
                no_replace
            ) != 0) {
            status = no_replace && errno == EEXIST ? PV_ERR_EXISTS : PV_ERR_IO;
        } else {
            published = true;
        }
    }
    if (status == PV_OK) {
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_ATOMIC_DIR_OPEN)) {
            status = PV_ERR_DURABILITY;
        } else
#endif
        {
#ifdef PVAULT_TEST_FAULT_INJECTION
            if (store_fault_point_triggered(PV_STORE_FAULT_POINT_ATOMIC_DIR_FSYNC)) {
                status = PV_ERR_DURABILITY;
            } else
#endif
            if (store_fsync(location->directory_fd) != 0) {
                status = PV_ERR_DURABILITY;
            }
        }
    }
    if (!published) {
        (void)unlinkat(location->directory_fd, temporary, 0);
    }
    return status;
}

static pv_status copy_file_exclusive_at(
    const int source_directory_fd,
    const char *const source_name,
    const int destination_directory_fd,
    const char *const destination_name
)
{
    char temporary[PATH_MAX];
    int input = -1;
    int output = -1;
    struct stat output_stat;
    uint8_t buffer[65536];
    pv_status status = PV_OK;
    bool published = false;
    unsigned attempt;

    if (source_directory_fd < 0 || source_name == NULL ||
        destination_directory_fd < 0 || destination_name == NULL) {
        return PV_ERR_USAGE;
    }
    status = open_private_snapshot_at(
        source_directory_fd,
        source_name,
        &input,
        NULL,
        NULL
    );
    if (status != PV_OK) {
        return status;
    }
    for (attempt = 0U; attempt < 32U; ++attempt) {
        uint32_t random_suffix;
        int written;

        randombytes_buf(&random_suffix, sizeof random_suffix);
        written = snprintf(
            temporary,
            sizeof temporary,
            "%s.tmp.%08x",
            destination_name,
            random_suffix
        );
        if (written < 0 || (size_t)written >= sizeof temporary) {
            (void)store_close(input);
            return PV_ERR_LIMIT;
        }
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_COPY_DEST_OPEN)) {
            output = -1;
        } else
#endif
        {
            output = store_openat(
                destination_directory_fd,
                temporary,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                0600
            );
        }
        if (output >= 0 || errno != EEXIST) {
            break;
        }
    }
    if (output < 0) {
        (void)store_close(input);
        return PV_ERR_IO;
    }
    if (fstat(output, &output_stat) != 0 ||
        private_snapshot_stat_issue(&output_stat) != PV_PRIVATE_SNAPSHOT_OK) {
        status = PV_ERR_IO;
    }
    while (status == PV_OK) {
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
    if (status == PV_OK && (fstat(output, &output_stat) != 0 ||
            private_snapshot_stat_issue(&output_stat) != PV_PRIVATE_SNAPSHOT_OK)) {
        status = PV_ERR_IO;
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
        if (store_renameat(
                destination_directory_fd,
                temporary,
                destination_directory_fd,
                destination_name,
                true
            ) != 0) {
            status = errno == EEXIST ? PV_ERR_EXISTS : PV_ERR_IO;
        } else {
            published = true;
        }
    }
    if (status == PV_OK) {
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_COPY_PARENT_FSYNC)) {
            status = PV_ERR_IO;
        } else
#endif
        {
            status = store_fsync(destination_directory_fd) == 0 ? PV_OK : PV_ERR_IO;
        }
    }
    sodium_memzero(buffer, sizeof(buffer));
    if (!published) {
        (void)unlinkat(destination_directory_fd, temporary, 0);
    }
    return status;
}

static pv_status write_snapshot_exclusive_at(
    const int directory_fd,
    const char *const name,
    const uint8_t header[PV_FILE_HEADER_LEN],
    const uint8_t *const ciphertext,
    const size_t ciphertext_len
)
{
    char temporary[PATH_MAX];
    int fd = -1;
    struct stat output_stat;
    pv_status status = PV_OK;
    bool published = false;
    unsigned attempt;

    if (directory_fd < 0 || name == NULL || header == NULL || ciphertext == NULL ||
        ciphertext_len == 0U) {
        return PV_ERR_USAGE;
    }
    for (attempt = 0U; attempt < 32U; ++attempt) {
        uint32_t random_suffix;
        int written;

        randombytes_buf(&random_suffix, sizeof random_suffix);
        written = snprintf(
            temporary,
            sizeof temporary,
            "%s.tmp.%08x",
            name,
            random_suffix
        );
        if (written < 0 || (size_t)written >= sizeof temporary) {
            return PV_ERR_LIMIT;
        }
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_SNAPSHOT_OPEN)) {
            fd = -1;
        } else
#endif
        {
            fd = store_openat(
                directory_fd,
                temporary,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                0600
            );
        }
        if (fd >= 0 || errno != EEXIST) {
            break;
        }
    }
    if (fd < 0) {
        return PV_ERR_IO;
    }
    status = fstat(fd, &output_stat) == 0 &&
        private_snapshot_stat_issue(&output_stat) == PV_PRIVATE_SNAPSHOT_OK
        ? PV_OK
        : PV_ERR_IO;
    if (status == PV_OK) {
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_SNAPSHOT_WRITE)) {
            status = PV_ERR_IO;
        } else
#endif
        {
            status = write_all(fd, header, PV_FILE_HEADER_LEN);
        }
    }
    if (status == PV_OK) status = write_all(fd, ciphertext, ciphertext_len);
    if (status == PV_OK && (fstat(fd, &output_stat) != 0 ||
            private_snapshot_stat_issue(&output_stat) != PV_PRIVATE_SNAPSHOT_OK)) {
        status = PV_ERR_IO;
    }
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
        if (store_renameat(directory_fd, temporary, directory_fd, name, true) != 0) {
            status = errno == EEXIST ? PV_ERR_EXISTS : PV_ERR_IO;
        } else {
            published = true;
        }
    }
    if (status == PV_OK) {
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_SNAPSHOT_PARENT_FSYNC)) {
            status = PV_ERR_DURABILITY;
        } else
#endif
        {
            status = store_fsync(directory_fd) == 0 ? PV_OK : PV_ERR_DURABILITY;
        }
    }
    if (!published) {
        (void)unlinkat(directory_fd, temporary, 0);
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
    pv_store_location location;
    pv_status status;

    status = open_store_location(destination, &location, NULL);
    if (status != PV_OK) {
        return status;
    }
    status = write_snapshot_exclusive_at(
        location.directory_fd,
        location.name,
        header,
        ciphertext,
        ciphertext_len
    );
    if (status == PV_OK && revalidate_store_location(destination, &location) != PV_OK) {
        status = PV_ERR_DURABILITY;
    }
    close_store_location(&location);
    return status;
}

#define PV_AUTO_BACKUP_PREFIX "auto-v1-"
#define PV_AUTO_BACKUP_NAME_LEN 67U
#define PV_AUTO_BACKUP_NAME_SIZE (PV_AUTO_BACKUP_NAME_LEN + 1U)
#define PV_AUTO_BACKUP_VAULT_OFFSET 8U
#define PV_AUTO_BACKUP_MARKER_OFFSET 40U
#define PV_AUTO_BACKUP_GENERATION_OFFSET 42U
#define PV_AUTO_BACKUP_EXTENSION_OFFSET 62U

typedef struct pv_backup_candidate {
    char name[PV_AUTO_BACKUP_NAME_SIZE];
    uint64_t generation;
    dev_t device;
    ino_t inode;
} pv_backup_candidate;

static int lowercase_hex_value(const char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    return -1;
}

static pv_status format_automatic_backup_name(
    const uint8_t vault_id[PV_VAULT_ID_BYTES],
    const uint64_t generation,
    char output[PV_AUTO_BACKUP_NAME_SIZE]
)
{
    char vault_hex[PV_VAULT_ID_BYTES * 2U + 1U];
    int written;

    if (vault_id == NULL || output == NULL || generation == 0U) {
        return PV_ERR_USAGE;
    }
    pv_hex_encode(vault_id, PV_VAULT_ID_BYTES, vault_hex, sizeof vault_hex);
    if (vault_hex[0] == '\0') {
        return PV_ERR_STATE;
    }
    written = snprintf(
        output,
        PV_AUTO_BACKUP_NAME_SIZE,
        PV_AUTO_BACKUP_PREFIX "%s-g%020llu.pvlt",
        vault_hex,
        (unsigned long long)generation
    );
    sodium_memzero(vault_hex, sizeof vault_hex);
    return written == (int)PV_AUTO_BACKUP_NAME_LEN ? PV_OK : PV_ERR_LIMIT;
}

static bool parse_automatic_backup_name(
    const char *const name,
    uint8_t vault_id[PV_VAULT_ID_BYTES],
    uint64_t *const generation
)
{
    uint64_t parsed_generation = 0U;
    size_t index;

    if (name == NULL || vault_id == NULL || generation == NULL ||
        strlen(name) != PV_AUTO_BACKUP_NAME_LEN ||
        memcmp(name, PV_AUTO_BACKUP_PREFIX, sizeof(PV_AUTO_BACKUP_PREFIX) - 1U) != 0 ||
        memcmp(name + PV_AUTO_BACKUP_MARKER_OFFSET, "-g", 2U) != 0 ||
        memcmp(name + PV_AUTO_BACKUP_EXTENSION_OFFSET, ".pvlt", 5U) != 0) {
        return false;
    }
    for (index = 0U; index < PV_VAULT_ID_BYTES; ++index) {
        const int high = lowercase_hex_value(
            name[PV_AUTO_BACKUP_VAULT_OFFSET + index * 2U]
        );
        const int low = lowercase_hex_value(
            name[PV_AUTO_BACKUP_VAULT_OFFSET + index * 2U + 1U]
        );

        if (high < 0 || low < 0) {
            sodium_memzero(vault_id, PV_VAULT_ID_BYTES);
            return false;
        }
        vault_id[index] = (uint8_t)((unsigned)high * 16U + (unsigned)low);
    }
    for (index = 0U; index < 20U; ++index) {
        const char digit_char = name[PV_AUTO_BACKUP_GENERATION_OFFSET + index];
        uint64_t digit;

        if (digit_char < '0' || digit_char > '9') {
            sodium_memzero(vault_id, PV_VAULT_ID_BYTES);
            return false;
        }
        digit = (uint64_t)(unsigned)(digit_char - '0');
        if (parsed_generation > (UINT64_MAX - digit) / 10U) {
            sodium_memzero(vault_id, PV_VAULT_ID_BYTES);
            return false;
        }
        parsed_generation = parsed_generation * 10U + digit;
    }
    if (parsed_generation == 0U) {
        sodium_memzero(vault_id, PV_VAULT_ID_BYTES);
        return false;
    }
    *generation = parsed_generation;
    return true;
}

static int compare_backup_candidates(const void *const left, const void *const right)
{
    const pv_backup_candidate *const a = left;
    const pv_backup_candidate *const b = right;

    if (a->generation < b->generation) return -1;
    if (a->generation > b->generation) return 1;
    return strcmp(a->name, b->name);
}

static pv_status validate_automatic_backup_entry(
    const int directory_fd,
    const char *const name,
    const uint8_t vault_id[PV_VAULT_ID_BYTES],
    const uint8_t vmk[PV_WRAP_KEY_BYTES],
    const uint64_t expected_generation,
    struct stat *const output_stat
)
{
    pv_disk_file disk;
    pv_buffer plaintext = {0};
    pv_vault decoded = {0};
    pv_status status;
    bool model_initialized = false;

    if (directory_fd < 0 || name == NULL || vault_id == NULL || vmk == NULL ||
        expected_generation == 0U) {
        return PV_ERR_USAGE;
    }
    status = read_disk_file_at(directory_fd, name, &disk);
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
        status = pv_model_init(&decoded, ".");
        model_initialized = status == PV_OK;
    }
    if (status == PV_OK) {
        status = pv_cbor_decode(plaintext.data, plaintext.len, &decoded);
    }
    if (status == PV_OK &&
        (sodium_memcmp(disk.header.vault_id, vault_id, PV_VAULT_ID_BYTES) != 0 ||
         decoded.generation != expected_generation)) {
        status = PV_ERR_AUTH;
    }
    if (status == PV_OK && output_stat != NULL) {
        *output_stat = disk.snapshot_stat;
    }
    if (model_initialized) {
        pv_model_destroy(&decoded);
    }
    pv_buffer_secure_free(&plaintext);
    disk_file_destroy(&disk);
    return status;
}

static pv_status prune_automatic_backups(
    const int held_directory_fd,
    const uint8_t vault_id[PV_VAULT_ID_BYTES],
    const uint8_t vmk[PV_WRAP_KEY_BYTES],
    const uint64_t maximum_generation,
    const unsigned retention
)
{
    pv_backup_candidate *candidates = NULL;
    size_t count = 0U;
    size_t capacity = 0U;
    size_t remove_count;
    size_t index;
    int directory_fd;
    int scan_fd;
    DIR *stream = NULL;
    pv_status status = PV_OK;
    bool deleted = false;

    if (held_directory_fd < 0 || vault_id == NULL || vmk == NULL ||
        maximum_generation == 0U || retention == 0U) {
        return PV_ERR_USAGE;
    }
    {
        struct stat directory_stat;

        if (fstat(held_directory_fd, &directory_stat) != 0 ||
            !S_ISDIR(directory_stat.st_mode) || directory_stat.st_uid != geteuid() ||
            (directory_stat.st_mode & 07777) != 0700) {
            return PV_ERR_IO;
        }
    }
    scan_fd = fcntl(held_directory_fd, F_DUPFD_CLOEXEC, 0);
    if (scan_fd < 0) {
        return PV_ERR_IO;
    }
    stream = fdopendir(scan_fd);
    if (stream == NULL) {
        (void)store_close(scan_fd);
        return PV_ERR_IO;
    }
    directory_fd = dirfd(stream);
    if (directory_fd < 0) {
        status = PV_ERR_IO;
        goto cleanup;
    }
    for (;;) {
        struct dirent *entry;
        uint8_t parsed_vault_id[PV_VAULT_ID_BYTES];
        uint64_t generation;
        struct stat listed_stat;
        struct stat opened_stat;

        errno = 0;
        entry = readdir(stream);
        if (entry == NULL) {
            if (errno != 0) status = PV_ERR_IO;
            break;
        }
        if (!parse_automatic_backup_name(entry->d_name, parsed_vault_id, &generation)) {
            continue;
        }
        if (sodium_memcmp(parsed_vault_id, vault_id, PV_VAULT_ID_BYTES) != 0) {
            sodium_memzero(parsed_vault_id, sizeof parsed_vault_id);
            continue;
        }
        sodium_memzero(parsed_vault_id, sizeof parsed_vault_id);
        if (fstatat(directory_fd, entry->d_name, &listed_stat, AT_SYMLINK_NOFOLLOW) != 0 ||
            private_snapshot_stat_issue(&listed_stat) != PV_PRIVATE_SNAPSHOT_OK) {
            status = PV_ERR_IO;
            break;
        }
        status = validate_automatic_backup_entry(
            directory_fd,
            entry->d_name,
            vault_id,
            vmk,
            generation,
            &opened_stat
        );
        if (status != PV_OK || listed_stat.st_dev != opened_stat.st_dev ||
            listed_stat.st_ino != opened_stat.st_ino) {
            if (status == PV_OK) status = PV_ERR_IO;
            break;
        }
        if ((opened_stat.st_mode & 07777) == 0400) {
            continue;
        }
        if (generation > maximum_generation) {
            continue;
        }
        if (count == capacity) {
            const size_t next = capacity == 0U ? 32U : capacity * 2U;
            size_t bytes;
            pv_backup_candidate *grown;

            if (next < capacity || !pv_size_mul(next, sizeof(*candidates), &bytes)) {
                status = PV_ERR_LIMIT;
                break;
            }
            grown = realloc(candidates, bytes);
            if (grown == NULL) {
                status = PV_ERR_NOMEM;
                break;
            }
            candidates = grown;
            capacity = next;
        }
        (void)memcpy(
            candidates[count].name,
            entry->d_name,
            PV_AUTO_BACKUP_NAME_SIZE
        );
        candidates[count].generation = generation;
        candidates[count].device = opened_stat.st_dev;
        candidates[count].inode = opened_stat.st_ino;
        ++count;
    }
    if (status != PV_OK || count <= retention) {
        goto cleanup;
    }
    qsort(candidates, count, sizeof(*candidates), compare_backup_candidates);
    remove_count = count - retention;
    for (index = 0U; index < remove_count; ++index) {
        struct stat current;

        if (fstatat(
                directory_fd,
                candidates[index].name,
                &current,
                AT_SYMLINK_NOFOLLOW
            ) != 0 || private_snapshot_stat_issue(&current) != PV_PRIVATE_SNAPSHOT_OK ||
            current.st_dev != candidates[index].device ||
            current.st_ino != candidates[index].inode) {
            status = PV_ERR_IO;
            goto cleanup;
        }
    }
#ifdef PVAULT_TEST_FAULT_INJECTION
    if (store_fault_point_triggered(PV_STORE_FAULT_POINT_PRUNE_UNLINK)) {
        status = PV_ERR_IO;
        goto cleanup;
    }
#endif
    for (index = 0U; index < remove_count; ++index) {
        struct stat current;

        if (fstatat(
                directory_fd,
                candidates[index].name,
                &current,
                AT_SYMLINK_NOFOLLOW
            ) != 0 || private_snapshot_stat_issue(&current) != PV_PRIVATE_SNAPSHOT_OK ||
            current.st_dev != candidates[index].device ||
            current.st_ino != candidates[index].inode ||
            unlinkat(directory_fd, candidates[index].name, 0) != 0) {
            status = PV_ERR_IO;
            goto cleanup;
        }
        deleted = true;
#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(
                PV_STORE_FAULT_POINT_PRUNE_AFTER_FIRST_UNLINK
            )) {
            status = PV_ERR_IO;
            goto cleanup;
        }
#endif
    }
cleanup:
    if (deleted) {
        pv_status sync_status = PV_OK;

#ifdef PVAULT_TEST_FAULT_INJECTION
        if (store_fault_point_triggered(PV_STORE_FAULT_POINT_PRUNE_DIR_FSYNC)) {
            sync_status = PV_ERR_DURABILITY;
        } else
#endif
        if (store_fsync(directory_fd) != 0) {
            sync_status = PV_ERR_DURABILITY;
        }
        if (status == PV_OK && sync_status != PV_OK) {
            status = sync_status;
        }
    }
    if (stream != NULL && closedir(stream) != 0 && status == PV_OK) {
        status = PV_ERR_IO;
    }
    free(candidates);
    return status;
}

static pv_status automatic_backup(
    const pv_store_location *const active_location,
    const pv_vault *const vault,
    const pv_disk_file *const snapshot,
    const uint64_t snapshot_generation,
    int *const backup_directory_fd
)
{
    char backup_name[PV_AUTO_BACKUP_NAME_SIZE];
    pv_status status;

    if (active_location == NULL || active_location->directory_fd < 0 ||
        vault == NULL || snapshot == NULL || backup_directory_fd == NULL) {
        return PV_ERR_USAGE;
    }
    *backup_directory_fd = -1;
    status = make_private_directory_at(
        active_location->directory_fd,
        "backups",
        backup_directory_fd
    );
    if (status != PV_OK) {
        return status;
    }
    status = format_automatic_backup_name(
        vault->vault_id,
        snapshot_generation,
        backup_name
    );
    if (status != PV_OK) {
        return status;
    }
    status = write_snapshot_exclusive_at(
        *backup_directory_fd,
        backup_name,
        snapshot->header_bytes,
        snapshot->ciphertext,
        snapshot->ciphertext_len
    );
    if (status == PV_ERR_DURABILITY) {
        status = PV_ERR_IO;
    }
    if (status == PV_ERR_EXISTS) {
        pv_disk_file existing;

        status = read_disk_file_at(*backup_directory_fd, backup_name, &existing);
        if (status == PV_OK &&
            (sodium_memcmp(existing.header.vault_id, vault->vault_id, PV_VAULT_ID_BYTES) != 0 ||
             sodium_memcmp(existing.hash, snapshot->hash, sizeof existing.hash) != 0)) {
            status = PV_ERR_EXISTS;
        } else if (status == PV_ERR_FORMAT || status == PV_ERR_UNSUPPORTED) {
            status = PV_ERR_EXISTS;
        } else if (status == PV_OK && store_fsync(*backup_directory_fd) != 0) {
            status = PV_ERR_IO;
        }
        if (status == PV_OK || status == PV_ERR_EXISTS) {
            disk_file_destroy(&existing);
        }
    }
    if (status != PV_OK) {
        (void)store_close(*backup_directory_fd);
        *backup_directory_fd = -1;
    }
    return status;
}

static pv_status save_locked(
    const pv_store_location *const location,
    pv_vault *const vault,
    pv_file_header *const header,
    const unsigned retention,
    const bool create_only
)
{
    pv_buffer encoded = { 0 };
    pv_buffer ciphertext = { 0 };
    uint8_t header_bytes[PV_FILE_HEADER_LEN];
    pv_disk_file current;
    uint64_t previous_generation;
    int64_t previous_updated_ms;
    int backup_directory_fd = -1;
    pv_status status;
    bool committed = false;
    bool commit_warning = false;
    bool verified = false;
    bool current_loaded = false;
    bool backup_ready = false;
    bool exists = false;

    if (vault->generation == UINT64_MAX) {
        return PV_ERR_LIMIT;
    }
    previous_generation = vault->generation;
    previous_updated_ms = vault->updated_ms;
    status = path_entry_exists_at(location->directory_fd, location->name, &exists);
    if (status != PV_OK) {
        return status;
    }
    if ((create_only && exists) || (!create_only && !exists)) {
        return create_only ? PV_ERR_EXISTS : PV_ERR_LOCKED;
    }

    if (exists) {
        status = read_disk_file_at(location->directory_fd, location->name, &current);
        if (status != PV_OK) {
            return status;
        }
        current_loaded = true;
        if ((current.snapshot_stat.st_mode & 07777) != 0600) {
            disk_file_destroy(&current);
            return PV_ERR_IO;
        }
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
        status = automatic_backup(
            location,
            vault,
            &current,
            previous_generation,
            &backup_directory_fd
        );
        backup_ready = status == PV_OK;
    }
    if (status == PV_OK && revalidate_store_location(vault->path, location) != PV_OK) {
        status = PV_ERR_LOCKED;
    }
    if (status == PV_OK) {
        status = write_atomic_at(
            location,
            header_bytes,
            ciphertext.data,
            ciphertext.len,
            create_only
        );
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
            readback_status = read_disk_file_at(
                location->directory_fd,
                location->name,
                &written
            );
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
        if (revalidate_store_location(vault->path, location) != PV_OK) {
            commit_warning = true;
        }
    }
    if (committed && verified) {
        vault->dirty = false;
        (void)pv_arena_set_readonly(&vault->arena);
        if (!commit_warning && backup_ready) {
            (void)prune_automatic_backups(
                backup_directory_fd,
                vault->vault_id,
                vault->vmk,
                previous_generation,
                retention
            );
        }
    } else if (!committed) {
        --vault->generation;
        vault->updated_ms = previous_updated_ms;
    }
    pv_buffer_secure_free(&ciphertext);
    pv_buffer_secure_free(&encoded);
    if (current_loaded) disk_file_destroy(&current);
    if (backup_directory_fd >= 0) {
        (void)store_close(backup_directory_fd);
    }
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
    pv_store_location location = { .directory_fd = -1 };
    int lock_fd = -1;
    pv_status status;
    char parent[PATH_MAX];
    bool exists = false;

    if (path == NULL || password == NULL || recovery_key == NULL || vault == NULL) {
        return PV_ERR_USAGE;
    }
    status = ensure_parent_directory(path, parent, sizeof(parent));
    if (status != PV_OK) {
        return status;
    }
    status = lock_vault(path, &location, &lock_fd);
    if (status != PV_OK) {
        return status;
    }
    status = path_entry_exists_at(location.directory_fd, location.name, &exists);
    if (status != PV_OK || exists) {
        unlock_vault(lock_fd, &location);
        return status != PV_OK ? status : PV_ERR_EXISTS;
    }
    status = pv_model_init(vault, path);
    if (status != PV_OK) {
        unlock_vault(lock_fd, &location);
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
        status = save_locked(
            &location,
            vault,
            &header,
            PV_DEFAULT_BACKUP_RETENTION,
            true
        );
    }
    sodium_memzero(&header, sizeof(header));
    unlock_vault(lock_fd, &location);
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
    pv_store_location location = { .directory_fd = -1 };
    int lock_fd = -1;
    pv_status status;

    if (vault == NULL || header == NULL || !vault->dirty || backup_retention == 0U) {
        return vault != NULL && !vault->dirty ? PV_OK : PV_ERR_USAGE;
    }
    status = lock_vault(vault->path, &location, &lock_fd);
    if (status != PV_OK) {
        return status;
    }
    status = save_locked(&location, vault, header, backup_retention, false);
    unlock_vault(lock_fd, &location);
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
    pv_store_location location = { .directory_fd = -1 };
    int lock_fd = -1;
    int backup_directory_fd = -1;
    pv_status status;
    bool active_exists = false;
    bool committed = false;
    bool commit_warning = false;

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
    status = lock_vault(vault_path, &location, &lock_fd);
    if (status == PV_OK) {
        status = path_entry_exists_at(
            location.directory_fd,
            location.name,
            &active_exists
        );
        if (status == PV_OK && active_exists) {
            char pre_restore[PATH_MAX];
            int written;
            pv_disk_file active;

            status = read_disk_file_at(
                location.directory_fd,
                location.name,
                &active
            );
            if (status == PV_ERR_FORMAT || status == PV_ERR_UNSUPPORTED) {
                status = PV_ERR_EXISTS;
            }
            if (status == PV_OK) {
                if (sodium_memcmp(
                        active.header.vault_id,
                        backup.header.vault_id,
                        PV_VAULT_ID_BYTES
                    ) != 0) {
                    status = PV_ERR_AUTH;
                }
                disk_file_destroy(&active);
            }

            if (status == PV_OK) {
                status = make_private_directory_at(
                    location.directory_fd,
                    "backups",
                    &backup_directory_fd
                );
            }
            if (status == PV_OK) {
                uint32_t suffix;
                randombytes_buf(&suffix, sizeof(suffix));
                written = snprintf(
                    pre_restore,
                    sizeof(pre_restore),
                    "pre-restore-%020lld-%08x.pvlt",
                    (long long)pv_now_ms(),
                    suffix
                );
                if (written < 0 || (size_t)written >= sizeof(pre_restore)) {
                    status = PV_ERR_LIMIT;
                } else {
                    status = copy_file_exclusive_at(
                        location.directory_fd,
                        location.name,
                        backup_directory_fd,
                        pre_restore
                    );
                }
            }
        }
    }
    if (backup_directory_fd >= 0) {
        (void)store_close(backup_directory_fd);
        backup_directory_fd = -1;
    }
    if (status == PV_OK && revalidate_store_location(vault_path, &location) != PV_OK) {
        status = PV_ERR_LOCKED;
    }
    if (status == PV_OK) {
        status = write_atomic_at(
            &location,
            backup.header_bytes,
            backup.ciphertext,
            backup.ciphertext_len,
            !active_exists
        );
        if (status == PV_OK || status == PV_ERR_DURABILITY) {
            committed = true;
            commit_warning = status == PV_ERR_DURABILITY;
            status = PV_OK;
        }
    }
    if (committed) {
        pv_disk_file written;
        pv_status readback_status = read_disk_file_at(
            location.directory_fd,
            location.name,
            &written
        );

        if (readback_status != PV_OK || written.ciphertext_len != backup.ciphertext_len ||
            sodium_memcmp(
                written.header_bytes,
                backup.header_bytes,
                sizeof backup.header_bytes
            ) != 0 || sodium_memcmp(
                written.ciphertext,
                backup.ciphertext,
                backup.ciphertext_len
            ) != 0) {
            commit_warning = true;
        }
        if (readback_status == PV_OK) {
            disk_file_destroy(&written);
        }
        if (revalidate_store_location(vault_path, &location) != PV_OK) {
            commit_warning = true;
        }
    }
    unlock_vault(lock_fd, &location);
    disk_file_destroy(&backup);
    if (committed && commit_warning) {
        return PV_ERR_DURABILITY;
    }
    return status;
}

pv_status pv_store_doctor(const char *const path, char *const message, const size_t message_len)
{
    pv_disk_file disk;
    struct stat st;
    struct stat lock_st;
    pv_private_snapshot_issue issue;
    char lock_path[PATH_MAX];
    int lock_length;
    bool lock_unsafe = false;
    pv_status status;

    if (path == NULL || message == NULL || message_len == 0U) {
        return PV_ERR_USAGE;
    }
    if (lstat(path, &st) != 0) {
        (void)snprintf(message, message_len, "vault path is inaccessible");
        return PV_ERR_IO;
    }
    issue = private_snapshot_stat_issue(&st);
    if (issue != PV_PRIVATE_SNAPSHOT_OK) {
        status = PV_ERR_IO;
        switch (issue) {
        case PV_PRIVATE_SNAPSHOT_TYPE:
            (void)snprintf(message, message_len, "vault path is not a regular non-symlink file");
            break;
        case PV_PRIVATE_SNAPSHOT_OWNER:
            (void)snprintf(message, message_len, "vault file is not owned by the current user");
            break;
        case PV_PRIVATE_SNAPSHOT_LINKS:
            (void)snprintf(message, message_len, "vault file has additional hard links");
            break;
        case PV_PRIVATE_SNAPSHOT_MODE:
            (void)snprintf(message, message_len, "vault permissions must be exactly 0400 or 0600");
            break;
        case PV_PRIVATE_SNAPSHOT_OK:
        case PV_PRIVATE_SNAPSHOT_PATH:
        case PV_PRIVATE_SNAPSHOT_PARENT:
            (void)snprintf(message, message_len, "vault path metadata is unsafe");
            break;
        }
        return status;
    }
    if (validate_parent_security(path) != PV_OK) {
        (void)snprintf(message, message_len, "vault parent directory is unsafe or writable by another user");
        return PV_ERR_IO;
    }
    lock_length = snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
    if (lock_length < 0 || (size_t)lock_length >= sizeof(lock_path)) {
        lock_unsafe = true;
    } else if (lstat(lock_path, &lock_st) != 0) {
        lock_unsafe = errno != ENOENT;
    } else {
        lock_unsafe = !S_ISREG(lock_st.st_mode) || S_ISLNK(lock_st.st_mode) ||
            lock_st.st_uid != geteuid() || lock_st.st_nlink != 1 ||
            (lock_st.st_mode & 07777) != 0600;
    }
    if (lock_unsafe) {
        (void)snprintf(message, message_len, "vault lockfile ownership or permissions are unsafe");
        return PV_ERR_IO;
    }
    status = read_disk_file(path, &disk);
    if (status != PV_OK) {
        (void)snprintf(message, message_len, "vault structure invalid: %s", pv_status_string(status));
        return status;
    }
    (void)snprintf(
        message,
        message_len,
        "structure OK; format %u.%u; encrypted payload %zu bytes",
        disk.header.major,
        disk.header.minor,
        disk.ciphertext_len
    );
    disk_file_destroy(&disk);
    return status;
}
