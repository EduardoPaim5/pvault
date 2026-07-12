#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly root_dir="$(cd -- "$script_dir/.." && pwd -P)"
readonly build_dir="${PVAULT_FUZZ_BUILD_DIR:-$root_dir/build/fuzz}"
readonly state_dir="${PVAULT_FUZZ_STATE_DIR:-$root_dir/.cache/fuzz}"
readonly runs="${PVAULT_FUZZ_RUNS:-2000}"
readonly timeout_seconds="${PVAULT_FUZZ_TIMEOUT:-10}"

usage() {
    cat <<'EOF'
Usage: scripts/fuzz-smoke.sh [fuzz_header|fuzz_cbor|fuzz_recovery ...]

With no target, all three fuzzers run. The evolving local corpus and crash
artifacts are kept under .cache/fuzz by default and are never uploaded.

Environment:
  PVAULT_FUZZ_RUNS       Inputs per target (default: 2000)
  PVAULT_FUZZ_TIMEOUT    Per-input timeout in seconds (default: 10)
  PVAULT_FUZZ_BUILD_DIR  Existing/new Clang fuzz build directory
  PVAULT_FUZZ_STATE_DIR  Persistent corpus/artifact root
EOF
}

die() {
    printf 'fuzz-smoke: %s\n' "$*" >&2
    exit 2
}

require_command() {
    command -v -- "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

validate_unsigned() {
    local name=$1
    local value=$2

    [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer"
}

validate_target() {
    case "$1" in
        fuzz_header|fuzz_cbor|fuzz_recovery) ;;
        *) die "unknown fuzz target: $1" ;;
    esac
}

ensure_private_dir() {
    local directory=$1
    local mode
    local owner

    [[ ! -L "$directory" ]] || die "refusing symlinked directory: $directory"
    if [[ -e "$directory" ]]; then
        [[ -d "$directory" ]] || die "not a directory: $directory"
    else
        mkdir -m 700 -p -- "$directory"
    fi
    owner="$(stat -c '%u' -- "$directory")"
    [[ "$owner" == "$EUID" ]] || die "directory is not owned by current user: $directory"
    mode="$(stat -c '%a' -- "$directory")"
    (( (8#$mode & 0700) == 0700 && (8#$mode & 077) == 0 )) || \
        die "directory must be owner-rwx and private (mode $mode): $directory"
}

seed_corpus() {
    local target=$1
    local corpus_dir=$2
    local seed

    for seed in "$root_dir/fuzz/seeds/$target"/*.b64; do
        local name
        local destination
        local temporary

        [[ -f "$seed" ]] || continue
        name="$(basename -- "${seed%.b64}")"
        destination="$corpus_dir/seed-$name"
        [[ -e "$destination" ]] && continue
        temporary="$(mktemp "$corpus_dir/.seed.XXXXXX")"
        if ! base64 --decode -- "$seed" >"$temporary"; then
            rm -f -- "$temporary"
            die "invalid seed encoding: $seed"
        fi
        chmod 600 "$temporary"
        mv -f -- "$temporary" "$destination"
    done
}

max_length_for() {
    case "$1" in
        fuzz_header) printf '%s\n' 4096 ;;
        fuzz_cbor) printf '%s\n' 2097152 ;;
        fuzz_recovery) printf '%s\n' 4096 ;;
    esac
}

run_target() {
    local target=$1
    local binary="$build_dir/$target"
    local corpus_dir="$state_dir/corpus/$target"
    local artifact_dir="$state_dir/artifacts/$target"
    local max_len

    ensure_private_dir "$corpus_dir"
    ensure_private_dir "$artifact_dir"
    seed_corpus "$target" "$corpus_dir"
    max_len="$(max_length_for "$target")"

    printf '\n==> Fuzz smoke: %s (%s inputs, persistent corpus: %s)\n' \
        "$target" "$runs" "$corpus_dir"
    ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:halt_on_error=1:abort_on_error=1}" \
    UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
        "$binary" "$corpus_dir" \
            "-artifact_prefix=$artifact_dir/" \
            "-runs=$runs" \
            "-timeout=$timeout_seconds" \
            -rss_limit_mb=2048 \
            "-max_len=$max_len" \
            -print_final_stats=1
}

main() {
    local -a targets
    local target

    if [[ ${1:-} == -h || ${1:-} == --help ]]; then
        usage
        exit 0
    fi
    require_command base64
    require_command clang
    require_command cmake
    require_command ninja
    require_command stat
    validate_unsigned PVAULT_FUZZ_RUNS "$runs"
    validate_unsigned PVAULT_FUZZ_TIMEOUT "$timeout_seconds"
    case "$state_dir" in
        ''|/) die 'refusing unsafe PVAULT_FUZZ_STATE_DIR' ;;
    esac

    if [[ $# -eq 0 ]]; then
        targets=(fuzz_header fuzz_cbor fuzz_recovery)
    else
        targets=("$@")
    fi
    for target in "${targets[@]}"; do
        validate_target "$target"
    done

    ensure_private_dir "$state_dir"
    ensure_private_dir "$state_dir/corpus"
    ensure_private_dir "$state_dir/artifacts"

    cmake -S "$root_dir" -B "$build_dir" -G Ninja \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_C_COMPILER=clang \
        -DBUILD_TESTING=OFF \
        -DPVAULT_BUILD_FUZZERS=ON \
        -DPVAULT_ENABLE_HARDENING=OFF \
        -DPVAULT_WARNINGS_AS_ERRORS=ON
    cmake --build "$build_dir" --parallel

    for target in "${targets[@]}"; do
        run_target "$target"
    done
}

main "$@"
