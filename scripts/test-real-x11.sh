#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly root_dir="$(cd -- "$script_dir/.." && pwd -P)"
readonly build_dir="${PVAULT_X11_BUILD_DIR:-$root_dir/build/x11-system}"
readonly repeat="${PVAULT_X11_REPEAT:-1}"

die() {
    printf 'test-real-x11: %s\n' "$*" >&2
    exit 2
}

require_command() {
    command -v -- "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

main() {
    local -a build_arguments=(--parallel)
    local -a test_arguments=(
        --test-dir "$build_dir"
        -L real-clipboard
        --output-on-failure
        --timeout 45
    )

    require_command cmake
    require_command ctest
    require_command ninja
    require_command pkg-config
    require_command python3
    require_command xauth
    require_command xclip
    if ! command -v Xvfb >/dev/null 2>&1; then
        die 'Xvfb is missing; on Arch Linux install xorg-server-xvfb'
    fi
    [[ "$repeat" =~ ^[1-9][0-9]*$ ]] || die 'PVAULT_X11_REPEAT must be a positive integer'
    if [[ -n "${PVAULT_JOBS:-}" ]]; then
        [[ "$PVAULT_JOBS" =~ ^[1-9][0-9]*$ ]] || die 'PVAULT_JOBS must be a positive integer'
        build_arguments+=("$PVAULT_JOBS")
    fi

    cmake \
        -S "$root_dir" \
        -B "$build_dir" \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBUILD_TESTING=ON \
        -DPVAULT_BUILD_INTEGRATION_TESTS=OFF \
        -DPVAULT_BUILD_X11_SYSTEM_TESTS=ON \
        -DPVAULT_ENABLE_HARDENING=ON \
        -DPVAULT_WARNINGS_AS_ERRORS=ON
    cmake --build "$build_dir" "${build_arguments[@]}"
    if [[ "$repeat" -gt 1 ]]; then
        test_arguments+=(--repeat "until-fail:$repeat")
    fi
    ctest "${test_arguments[@]}"
}

main "$@"
