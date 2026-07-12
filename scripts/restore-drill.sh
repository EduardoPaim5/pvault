#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly root_dir="$(cd -- "$script_dir/.." && pwd -P)"

die() {
    printf 'restore-drill: %s\n' "$*" >&2
    exit 2
}

require_command() {
    command -v -- "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

main() {
    local build_dir
    local -a build_arguments=(--parallel)

    [[ $# -eq 0 ]] || die 'this script does not accept arguments'
    require_command python3

    if [[ -n "${PVAULT_BUILD_DIR:-}" ]]; then
        build_dir=$PVAULT_BUILD_DIR
        [[ -x "$build_dir/pvault" ]] || die "existing build is missing executable pvault: $build_dir"
    else
        build_dir="$root_dir/build/restore-drill"
        require_command cmake
        require_command ninja
        require_command pkg-config
        if [[ -n "${PVAULT_JOBS:-}" ]]; then
            [[ "$PVAULT_JOBS" =~ ^[1-9][0-9]*$ ]] || die 'PVAULT_JOBS must be a positive integer'
            build_arguments+=("$PVAULT_JOBS")
        fi
        cmake \
            -S "$root_dir" \
            -B "$build_dir" \
            -G Ninja \
            -DCMAKE_BUILD_TYPE=Debug \
            -DBUILD_TESTING=OFF \
            -DPVAULT_ENABLE_HARDENING=ON \
            -DPVAULT_ENABLE_SANITIZERS=OFF \
            -DPVAULT_BUILD_FUZZERS=OFF \
            -DPVAULT_WARNINGS_AS_ERRORS=ON
        cmake --build "$build_dir" --target pvault "${build_arguments[@]}"
    fi

    PVAULT_BUILD_DIR="$build_dir" \
    PYTHONDONTWRITEBYTECODE=1 \
        python3 "$root_dir/tests/integration/restore_drill.py"
}

main "$@"
