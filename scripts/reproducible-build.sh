#!/usr/bin/env bash

set -Eeuo pipefail
umask 022

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly root_dir="$(cd -- "$script_dir/.." && pwd -P)"
readonly work_dir="$root_dir/build/reproducible"
readonly compiler="${CC:-gcc}"

die() {
    printf 'reproducible-build: %s\n' "$*" >&2
    exit 2
}

require_command() {
    command -v -- "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

reset_work_tree() {
    case "$work_dir" in
        "$root_dir"/build/reproducible) ;;
        *) die 'refusing to reset an unexpected work directory' ;;
    esac
    cmake -E remove_directory "$work_dir"
    mkdir -p -- "$work_dir"
}

build_once() {
    local label=$1
    local build_dir="$work_dir/build-$label"
    local stage_dir="$work_dir/stage-$label"
    local map_flags

    map_flags="-Wdate-time -ffile-prefix-map=$build_dir=/usr/src/pvault/build"
    map_flags+=" -fdebug-prefix-map=$build_dir=/usr/src/pvault/build"
    map_flags+=" -fmacro-prefix-map=$build_dir=/usr/src/pvault/build"
    map_flags+=" -ffile-prefix-map=$root_dir=/usr/src/pvault"
    map_flags+=" -fdebug-prefix-map=$root_dir=/usr/src/pvault"
    map_flags+=" -fmacro-prefix-map=$root_dir=/usr/src/pvault"

    cmake -S "$root_dir" -B "$build_dir" -G Ninja \
        "-DCMAKE_C_COMPILER=$compiler" \
        -DCMAKE_BUILD_TYPE=Release \
        "-DCMAKE_C_FLAGS=$map_flags" \
        -DCMAKE_EXE_LINKER_FLAGS=-Wl,--build-id=sha1 \
        -DBUILD_TESTING=ON \
        -DPVAULT_ENABLE_HARDENING=ON \
        -DPVAULT_WARNINGS_AS_ERRORS=ON \
        -DPVAULT_ENABLE_SANITIZERS=OFF \
        -DPVAULT_BUILD_FUZZERS=OFF
    cmake --build "$build_dir" --parallel
    CC="$compiler" PVAULT_BUILD_DIR="$build_dir" \
        ctest --test-dir "$build_dir" --output-on-failure --timeout 180
    DESTDIR="$stage_dir" cmake --install "$build_dir" --prefix /usr
}

write_manifest() {
    local stage_dir=$1
    local output=$2

    (
        cd -- "$stage_dir"
        while IFS= read -r -d '' path; do
            local mode
            local relative=${path#./}

            mode="$(stat -c '%a' -- "$path")"
            if [[ -L "$path" ]]; then
                printf 'l\t%s\t%s\t%s\n' "$mode" "$relative" "$(readlink -- "$path")"
            elif [[ -d "$path" ]]; then
                printf 'd\t%s\t%s\n' "$mode" "$relative"
            elif [[ -f "$path" ]]; then
                local digest

                digest="$(sha256sum -- "$path")"
                digest=${digest%% *}
                printf 'f\t%s\t%s\t%s\n' "$mode" "$digest" "$relative"
            else
                printf 'o\t%s\t%s\n' "$mode" "$relative"
            fi
        done < <(find . -mindepth 1 -print0 | LC_ALL=C sort -z)
    ) >"$output"
}

main() {
    local epoch
    local first_manifest="$work_dir/manifest-a.txt"
    local second_manifest="$work_dir/manifest-b.txt"

    require_command "$compiler"
    require_command awk
    require_command cmake
    require_command ctest
    require_command diff
    require_command find
    require_command git
    require_command ninja
    require_command python3
    require_command sha256sum
    require_command sort
    require_command stat

    if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
        epoch=$SOURCE_DATE_EPOCH
    elif git -C "$root_dir" rev-parse --verify HEAD >/dev/null 2>&1; then
        epoch="$(git -C "$root_dir" log -1 --format=%ct)"
    else
        epoch=0
    fi
    [[ "$epoch" =~ ^[0-9]+$ ]] || die 'SOURCE_DATE_EPOCH must be an unsigned integer'

    export SOURCE_DATE_EPOCH="$epoch"
    export TZ=UTC
    export LC_ALL=C
    export LANG=C
    export ZERO_AR_DATE=1

    reset_work_tree
    printf '==> Reproducibility build A with %s (SOURCE_DATE_EPOCH=%s)\n' "$compiler" "$epoch"
    build_once a
    printf '==> Reproducibility build B with %s (SOURCE_DATE_EPOCH=%s)\n' "$compiler" "$epoch"
    build_once b

    write_manifest "$work_dir/stage-a" "$first_manifest"
    write_manifest "$work_dir/stage-b" "$second_manifest"
    if ! diff -u -- "$first_manifest" "$second_manifest"; then
        printf 'Installed trees differ; manifests remain under %s\n' "$work_dir" >&2
        exit 1
    fi
    printf 'Reproducible install tree verified: %s\n' \
        "$(sha256sum "$first_manifest" | awk '{print $1}')"
}

main "$@"
