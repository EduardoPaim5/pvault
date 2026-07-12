#include "cli.h"

#include <ctype.h>
#include <limits.h>
#include <curses.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    size_t position = 0U;

    (void)addch((record->flags & PV_RECORD_FAVORITE) != 0U ? '*' : ' ');
    (void)addch(' ');
    while (position < record->title.len) {
        size_t safe_start = position;

        while (position < record->title.len && record->title.data[position] >= 0x20U &&
               record->title.data[position] != 0x7fU) {
            ++position;
        }
        if (position > safe_start) {
            size_t remaining = position - safe_start;

            while (remaining > 0U) {
                const int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
                (void)addnstr((const char *)record->title.data + safe_start, chunk);
                safe_start += (size_t)chunk;
                remaining -= (size_t)chunk;
            }
        }
        if (position < record->title.len) {
            (void)addch('?');
            ++position;
        }
    }
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

    if (vault == NULL || selected == NULL || vault->record_count == 0U || !isatty(STDIN_FILENO)) {
        return PV_ERR_NOT_FOUND;
    }
    *selected = NULL;
    match_capacity = vault->record_count;
    matches = calloc(match_capacity, sizeof(*matches));
    if (matches == NULL) {
        return PV_ERR_NOMEM;
    }
    if (initscr() == NULL) {
        free(matches);
        return PV_ERR_EXTERNAL;
    }
    (void)cbreak();
    (void)noecho();
    (void)keypad(stdscr, TRUE);
    (void)curs_set(1);
    for (;;) {
        int rows;
        int columns;
        size_t i;
        size_t visible;
        size_t first;

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
        key = getch();
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
    (void)endwin();
    sodium_memzero(query, sizeof(query));
    free(matches);
    return status;
}
