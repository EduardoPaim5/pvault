#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly root_dir="$(cd -- "$script_dir/.." && pwd -P)"
readonly build_dir="${PVAULT_LIVE_X11_BUILD_DIR:-$root_dir/build/live-x11-manual}"
readonly acknowledgement='--acknowledge-live-clipboard-overwrite'

die() {
    printf 'test-live-x11-i3: %s\n' "$*" >&2
    exit 2
}

require_command() {
    command -v -- "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

main() {
    local -a environment=(
        "DISPLAY=${DISPLAY:-}"
        "HOME=${HOME:-}"
        'LANG=C'
        'LC_ALL=C'
        'PATH=/usr/bin:/bin'
        'PYTHONUTF8=1'
        'XDG_SESSION_TYPE=x11'
        "PVAULT_LIVE_X11_DRIVER=$build_dir/pvault_x11_clipboard_driver"
        "PVAULT_LIVE_X11_OWNER_QUERY=$build_dir/pvault_x11_selection_owner"
        'PVAULT_LIVE_X11_XCLIP=/usr/bin/xclip'
    )

    if [[ $# -ne 1 || "$1" != "$acknowledgement" ]]; then
        printf 'Usage: %s %s\n' "$0" "$acknowledgement" >&2
        exit 2
    fi
    [[ "$(uname -s)" == 'Linux' ]] || die 'this manual canary requires Linux'
    [[ "$(id -u)" -ne 0 ]] || die 'refusing to run as root'
    [[ -t 0 && -t 1 && -t 2 ]] || die 'stdin, stdout, and stderr must be terminals'
    [[ -r /dev/tty && -w /dev/tty ]] || die '/dev/tty must be readable and writable'
    [[ "${XDG_SESSION_TYPE:-}" == 'x11' ]] || die 'XDG_SESSION_TYPE must be exactly x11'
    [[ -z "${WAYLAND_DISPLAY:-}" ]] || die 'WAYLAND_DISPLAY must be empty'
    [[ -n "${DISPLAY:-}" ]] || die 'DISPLAY must be set'
    [[ -n "${HOME:-}" ]] || die 'HOME must be set'

    require_command cmake
    require_command ninja
    require_command pkg-config
    [[ -x /usr/bin/i3-msg ]] || die 'required executable not found: /usr/bin/i3-msg'
    [[ -x /usr/bin/python3 ]] || die 'required executable not found: /usr/bin/python3'
    [[ -x /usr/bin/xclip ]] || die 'required executable not found: /usr/bin/xclip'
    /usr/bin/python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' || \
        die '/usr/bin/python3 must be version 3.10 or newer'
    /usr/bin/env -u I3SOCK /usr/bin/i3-msg -t get_version >/dev/null 2>&1 || \
        die 'cannot reach the active i3 session through DISPLAY'

    if [[ -n "${XAUTHORITY:-}" ]]; then
        environment+=("XAUTHORITY=$XAUTHORITY")
    fi
    if [[ -n "${XDG_RUNTIME_DIR:-}" ]]; then
        environment+=("XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR")
    fi
    cmake \
        -S "$root_dir" \
        -B "$build_dir" \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=ON \
        -DPVAULT_BUILD_INTEGRATION_TESTS=OFF \
        -DPVAULT_BUILD_LIVE_X11_CANARY=ON \
        -DPVAULT_BUILD_X11_SYSTEM_TESTS=OFF \
        -DPVAULT_BUILD_WAYLAND_SYSTEM_TESTS=OFF \
        -DPVAULT_ENABLE_HARDENING=ON \
        -DPVAULT_WARNINGS_AS_ERRORS=ON
    cmake --build "$build_dir" --parallel --target \
        pvault-clip \
        pvault_x11_clipboard_driver \
        pvault_x11_selection_owner

    exec /usr/bin/env -i "${environment[@]}" \
        /usr/bin/python3 "$root_dir/tests/manual/test_live_x11_i3.py" \
        "$acknowledgement"
}

main "$@"
