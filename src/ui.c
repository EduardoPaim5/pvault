#include "cli.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <curses.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PV_UI_SIGNAL_COUNT 5U

typedef struct pv_ui_signal_guard {
    struct sigaction previous[PV_UI_SIGNAL_COUNT];
    sigset_t guarded;
    sigset_t previous_mask;
    size_t captured;
    bool mask_saved;
} pv_ui_signal_guard;

static const int pv_ui_signals[PV_UI_SIGNAL_COUNT] = {
    SIGINT,
    SIGTERM,
    SIGHUP,
    SIGQUIT,
    SIGTSTP
};
static volatile sig_atomic_t pv_ui_interrupted;

static void ui_signal_handler(const int signal_number)
{
    const int saved_errno = errno;

    if (pv_ui_interrupted == 0) {
        pv_ui_interrupted = signal_number;
    }
    errno = saved_errno;
}

static bool ui_signal_guard_prepare(pv_ui_signal_guard *const guard)
{
    size_t index;

    memset(guard, 0, sizeof(*guard));
    if (sigemptyset(&guard->guarded) != 0) return false;
    for (index = 0U; index < PV_UI_SIGNAL_COUNT; ++index) {
        if (sigaddset(&guard->guarded, pv_ui_signals[index]) != 0 ||
            sigaction(pv_ui_signals[index], NULL, &guard->previous[index]) != 0) {
            return false;
        }
        ++guard->captured;
    }
    if (sigprocmask(SIG_BLOCK, &guard->guarded, &guard->previous_mask) != 0) {
        return false;
    }
    guard->mask_saved = true;
    pv_ui_interrupted = 0;
    return true;
}

static bool ui_signal_guard_install(pv_ui_signal_guard *const guard)
{
    struct sigaction action;
    sigset_t active_mask;
    size_t index;

    memset(&action, 0, sizeof(action));
    action.sa_handler = ui_signal_handler;
    action.sa_mask = guard->guarded;
    for (index = 0U; index < guard->captured; ++index) {
        const struct sigaction *const disposition =
            guard->previous[index].sa_handler == SIG_IGN
                ? &guard->previous[index]
                : &action;

        if (sigaction(pv_ui_signals[index], disposition, NULL) != 0) {
            return false;
        }
    }
    active_mask = guard->previous_mask;
    for (index = 0U; index < guard->captured; ++index) {
        if (guard->previous[index].sa_handler != SIG_IGN &&
            sigdelset(&active_mask, pv_ui_signals[index]) != 0) {
            return false;
        }
    }
    return sigprocmask(SIG_SETMASK, &active_mask, NULL) == 0;
}

static void ui_signal_guard_block(const pv_ui_signal_guard *const guard)
{
    if (guard->mask_saved) {
        (void)sigprocmask(SIG_BLOCK, &guard->guarded, NULL);
    }
}

static bool ui_signal_guard_restore(pv_ui_signal_guard *const guard)
{
    bool restored = true;

    while (guard->captured > 0U) {
        --guard->captured;
        if (sigaction(
                pv_ui_signals[guard->captured],
                &guard->previous[guard->captured],
                NULL
            ) != 0) {
            restored = false;
        }
    }
    if (guard->mask_saved &&
        sigprocmask(SIG_SETMASK, &guard->previous_mask, NULL) != 0) {
        restored = false;
    }
    guard->mask_saved = false;
    return restored;
}

static bool ui_record_matches(const pv_record *const record, const char *const query)
{
    size_t i;

    if (query[0] == '\0') {
        return true;
    }
    if (pv_slice_contains_cstr(&record->title, query, true) ||
        pv_slice_contains_cstr(&record->username, query, true)) {
        return true;
    }
    for (i = 0U; i < record->url_count; ++i) {
        if (pv_slice_contains_cstr(&record->urls[i], query, true)) {
            return true;
        }
    }
    for (i = 0U; i < record->tag_count; ++i) {
        if (pv_slice_contains_cstr(&record->tags[i], query, true)) {
            return true;
        }
    }
    return false;
}

static size_t build_matches(
    pv_vault *const vault,
    const char *const query,
    pv_record **const matches,
    const size_t capacity
)
{
    size_t i;
    size_t count = 0U;

    for (i = 0U; i < vault->record_count; ++i) {
        if ((vault->records[i].flags & PV_RECORD_DELETED) == 0U &&
            ui_record_matches(&vault->records[i], query)) {
            if (count >= capacity) return count;
            matches[count++] = &vault->records[i];
        }
    }
    return count;
}

static void ui_add_safe_title(const pv_record *const record)
{
    uint8_t sanitized[PV_MAX_TITLE];
    size_t sanitized_len = 0U;
    size_t position = 0U;

    (void)addch((record->flags & PV_RECORD_FAVORITE) != 0U ? '*' : ' ');
    (void)addch(' ');
    if (!pv_text_sanitize(&record->title, sanitized, sizeof(sanitized), &sanitized_len)) {
        if (record->title.len > 0U) {
            (void)addch('?');
        }
        sodium_memzero(sanitized, sizeof(sanitized));
        return;
    }
    while (position < sanitized_len) {
        const size_t remaining = sanitized_len - position;
        const int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;

        (void)addnstr((const char *)sanitized + position, chunk);
        position += (size_t)chunk;
    }
    sodium_memzero(sanitized, sizeof(sanitized));
}

pv_status pv_ui_pick_internal(pv_vault *const vault, pv_record **const selected)
{
    pv_record **matches;
    char query[256] = { 0 };
    size_t query_len = 0U;
    size_t match_count;
    size_t current = 0U;
    size_t match_capacity;
    int key;
    pv_status status = PV_ERR_NOT_FOUND;
    int tty_input_fd = -1;
    int tty_output_fd = -1;
    FILE *tty_input = NULL;
    FILE *tty_output = NULL;
    SCREEN *screen = NULL;
    SCREEN *previous_screen = NULL;
    pv_ui_signal_guard signal_guard;
    bool signal_guard_prepared = false;
    bool curses_active = false;
    int caught_signal = 0;

    if (vault == NULL || selected == NULL || vault->record_count == 0U) {
        return PV_ERR_NOT_FOUND;
    }
    *selected = NULL;
    match_capacity = vault->record_count;
    matches = calloc(match_capacity, sizeof(*matches));
    if (matches == NULL) {
        return PV_ERR_NOMEM;
    }
    tty_input_fd = open("/dev/tty", O_RDONLY | O_CLOEXEC | O_NOCTTY);
    tty_output_fd = open("/dev/tty", O_WRONLY | O_CLOEXEC | O_NOCTTY);
    if (tty_input_fd < 0 || tty_output_fd < 0 ||
        !isatty(tty_input_fd) || !isatty(tty_output_fd)) {
        status = PV_ERR_IO;
        goto cleanup;
    }
    tty_input = fdopen(tty_input_fd, "r");
    if (tty_input == NULL) {
        status = PV_ERR_IO;
        goto cleanup;
    }
    tty_input_fd = -1;
    tty_output = fdopen(tty_output_fd, "w");
    if (tty_output == NULL) {
        status = PV_ERR_IO;
        goto cleanup;
    }
    tty_output_fd = -1;
    if (!ui_signal_guard_prepare(&signal_guard)) {
        status = PV_ERR_IO;
        goto cleanup;
    }
    signal_guard_prepared = true;
    screen = newterm(NULL, tty_output, tty_input);
    if (screen == NULL) {
        status = PV_ERR_EXTERNAL;
        goto cleanup;
    }
    previous_screen = set_term(screen);
    curses_active = true;
    if (!ui_signal_guard_install(&signal_guard)) {
        status = PV_ERR_IO;
        goto cleanup;
    }
    if (pv_ui_interrupted != 0) {
        status = PV_ERR_IO;
        goto cleanup;
    }
    if (cbreak() == ERR || noecho() == ERR || keypad(stdscr, TRUE) == ERR) {
        status = PV_ERR_EXTERNAL;
        goto cleanup;
    }
    timeout(100);
    (void)curs_set(1);
    for (;;) {
        int rows;
        int columns;
        size_t i;
        size_t visible;
        size_t first;

        if (pv_ui_interrupted != 0) {
            status = PV_ERR_IO;
            break;
        }
        match_count = build_matches(vault, query, matches, match_capacity);
        if (current >= match_count && match_count > 0U) {
            current = match_count - 1U;
        }
        getmaxyx(stdscr, rows, columns);
        (void)columns;
        (void)erase();
        (void)mvprintw(0, 0, "PVault search: %s", query);
        (void)mvprintw(1, 0, "%zu match%s — Enter select, Esc cancel", match_count, match_count == 1U ? "" : "es");
        visible = rows > 3 ? (size_t)(rows - 3) : 0U;
        first = current >= visible && visible > 0U ? current - visible + 1U : 0U;
        for (i = 0U; i < visible && first + i < match_count; ++i) {
            const size_t match_index = first + i;
            pv_record *record;

            if (match_index >= match_capacity) {
                status = PV_ERR_STATE;
                goto cleanup;
            }
            record = matches[match_index];
            if (first + i == current) {
                (void)attron(A_REVERSE);
            }
            (void)move((int)i + 3, 0);
            ui_add_safe_title(record);
            (void)clrtoeol();
            if (first + i == current) {
                (void)attroff(A_REVERSE);
            }
        }
        (void)move(0, (int)(strlen("PVault search: ") + query_len));
        (void)refresh();
        do {
            key = getch();
        } while (key == ERR && pv_ui_interrupted == 0);
        if (pv_ui_interrupted != 0) {
            status = PV_ERR_IO;
            break;
        }
        if (key == 27) {
            status = PV_ERR_NOT_FOUND;
            break;
        }
        if ((key == '\n' || key == KEY_ENTER) && match_count > 0U) {
            if (current >= match_capacity) {
                status = PV_ERR_STATE;
                break;
            }
            *selected = matches[current];
            status = PV_OK;
            break;
        }
        if (key == KEY_UP && current > 0U) {
            --current;
        } else if (key == KEY_DOWN && current + 1U < match_count) {
            ++current;
        } else if ((key == KEY_BACKSPACE || key == 127 || key == '\b') && query_len > 0U) {
            query[--query_len] = '\0';
            current = 0U;
        } else if (key >= 0x20 && key <= 0x7e && query_len + 1U < sizeof(query)) {
            query[query_len++] = (char)key;
            query[query_len] = '\0';
            current = 0U;
        }
    }
cleanup:
    if (signal_guard_prepared) {
        ui_signal_guard_block(&signal_guard);
        caught_signal = (int)pv_ui_interrupted;
    }
    if (curses_active) {
        (void)endwin();
    }
    if (screen != NULL) {
        if (previous_screen != NULL && previous_screen != screen) {
            (void)set_term(previous_screen);
        }
        delscreen(screen);
    }
    if (tty_output != NULL) {
        (void)fclose(tty_output);
    } else if (tty_output_fd >= 0) {
        (void)close(tty_output_fd);
    }
    if (tty_input != NULL) {
        (void)fclose(tty_input);
    } else if (tty_input_fd >= 0) {
        (void)close(tty_input_fd);
    }
    sodium_memzero(query, sizeof(query));
    free(matches);
    if (signal_guard_prepared && !ui_signal_guard_restore(&signal_guard)) {
        status = PV_ERR_IO;
    }
    pv_ui_interrupted = 0;
    if (caught_signal != 0) {
        (void)raise(caught_signal);
        return PV_ERR_IO;
    }
    return status;
}
