#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly root_dir="$(cd -- "$script_dir/.." && pwd -P)"

usage() {
    cat <<'EOF'
Usage: scripts/ci-build.sh PROFILE

Profiles:
  gcc       Debug build and tests with GCC
  clang     Debug build and tests with Clang
  sanitize  Debug build and tests with Clang ASan/UBSan
  lsan      Debug build and tests with standalone Clang LeakSanitizer
  release   Hardened Release build, tests, and staged install with GCC
  all       Run gcc, clang, sanitize, and release sequentially

Environment:
  PVAULT_JOBS  Optional build parallelism (a positive integer)
EOF
}

die() {
    printf 'ci-build: %s\n' "$*" >&2
    exit 2
}

require_command() {
    command -v -- "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

check_jobs() {
    if [[ -n "${PVAULT_JOBS:-}" && ! "${PVAULT_JOBS}" =~ ^[1-9][0-9]*$ ]]; then
        die 'PVAULT_JOBS must be a positive integer'
    fi
}

require_ptrace_capability() {
    local effective

    [[ -r /proc/self/status ]] || die 'lsan requires Linux /proc capability metadata'
    effective="$(awk '$1 == "CapEff:" { print $2 }' /proc/self/status)"
    [[ "$effective" =~ ^[0-9a-fA-F]+$ ]] || die 'could not read effective capabilities'
    if (( (16#$effective & 0x80000) == 0 )); then
        die 'lsan requires CAP_SYS_PTRACE because PVault keeps PR_SET_DUMPABLE=0; use the isolated container workflow'
    fi
}

assert_no_build_processes() {
    local build_dir=$1
    local attempt
    local executable
    local lingering=''
    local process

    for attempt in {1..20}; do
        lingering=''
        for process in /proc/[0-9]*; do
            executable="$(readlink -f -- "$process/exe" 2>/dev/null || true)"
            case "$executable" in
                "$build_dir"/*)
                    lingering+="${process##*/}:$executable"$'\n'
                    ;;
            esac
        done
        [[ -z "$lingering" ]] && return 0
        sleep 0.1
    done
    printf 'ci-build: leak profile left test processes running:\n%s' "$lingering" >&2
    return 1
}

build_parallel() {
    local build_dir=$1

    if [[ -n "${PVAULT_JOBS:-}" ]]; then
        cmake --build "$build_dir" --parallel "$PVAULT_JOBS"
    else
        cmake --build "$build_dir" --parallel
    fi
}

run_profile() {
    local profile=$1
    local compiler
    local build_type
    local sanitizers=OFF
    local lsan=OFF
    local build_dir="$root_dir/build/ci/$profile"
    local compiler_output
    local compiler_version
    local -a configure_args

    case "$profile" in
        gcc)
            compiler=gcc
            build_type=Debug
            ;;
        clang)
            compiler=clang
            build_type=Debug
            ;;
        sanitize)
            compiler=clang
            build_type=Debug
            sanitizers=ON
            ;;
        lsan)
            compiler=clang
            build_type=Debug
            lsan=ON
            require_ptrace_capability
            ;;
        release)
            compiler=gcc
            build_type=Release
            ;;
        *)
            die "unknown profile: $profile"
            ;;
    esac

    require_command "$compiler"
    compiler_output="$($compiler --version)"
    compiler_version=${compiler_output%%$'\n'*}
    printf '\n==> PVault CI profile: %s (%s)\n' "$profile" "$compiler_version"

    configure_args=(
        -S "$root_dir"
        -B "$build_dir"
        -G Ninja
        "-DCMAKE_C_COMPILER=$compiler"
        "-DCMAKE_BUILD_TYPE=$build_type"
        -DBUILD_TESTING=ON
        -DPVAULT_ENABLE_HARDENING=ON
        -DPVAULT_WARNINGS_AS_ERRORS=ON
        "-DPVAULT_ENABLE_SANITIZERS=$sanitizers"
        "-DPVAULT_ENABLE_LSAN=$lsan"
        -DPVAULT_BUILD_FUZZERS=OFF
    )
    cmake "${configure_args[@]}"
    build_parallel "$build_dir"

    if [[ "$profile" == sanitize ]]; then
        CC="$compiler" \
        PVAULT_BUILD_DIR="$build_dir" \
        ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:halt_on_error=1:abort_on_error=1}" \
        UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
            ctest --test-dir "$build_dir" --output-on-failure --timeout 180
    elif [[ "$profile" == lsan ]]; then
        local lsan_log_dir="$build_dir/lsan-logs"
        local lsan_status=0
        local report
        local reports_found=false

        cmake -E remove_directory "$lsan_log_dir"
        cmake -E make_directory "$lsan_log_dir"
        chmod 0700 "$lsan_log_dir"
        CC="$compiler" \
        PVAULT_BUILD_DIR="$build_dir" \
        LSAN_OPTIONS="detect_leaks=1:exitcode=23:max_leaks=50:report_objects=1:log_path=$lsan_log_dir/report" \
            ctest --test-dir "$build_dir" --output-on-failure --parallel 1 --timeout 240 || \
            lsan_status=$?
        assert_no_build_processes "$build_dir" || lsan_status=1
        while IFS= read -r -d '' report; do
            reports_found=true
            printf 'ci-build: LeakSanitizer report from %s:\n' "$report" >&2
            sed -n '1,240p' "$report" >&2
        done < <(find "$lsan_log_dir" -type f -size +0c -print0)
        if [[ "$reports_found" == true ]]; then
            lsan_status=1
        fi
        (( lsan_status == 0 )) || return "$lsan_status"
    else
        CC="$compiler" PVAULT_BUILD_DIR="$build_dir" \
            ctest --test-dir "$build_dir" --output-on-failure --timeout 180
    fi

    if [[ "$profile" == release ]]; then
        local stage_dir="$build_dir/stage"

        case "$stage_dir" in
            "$root_dir"/build/ci/release/stage) ;;
            *) die 'refusing to reset an unexpected staging path' ;;
        esac
        cmake -E remove_directory "$stage_dir"
        DESTDIR="$stage_dir" cmake --install "$build_dir" --prefix /usr
        test -x "$stage_dir/usr/bin/pvault"
        test -x "$stage_dir/usr/bin/pvault-clip"
        test -f "$stage_dir/usr/share/man/man1/pvault.1"
    fi
}

main() {
    local profile=${1:-}

    if [[ "$profile" == -h || "$profile" == --help ]]; then
        usage
        exit 0
    fi
    if [[ -z "$profile" || $# -ne 1 ]]; then
        usage >&2
        exit 2
    fi
    require_command cmake
    require_command ctest
    require_command ninja
    require_command pkg-config
    require_command python3
    check_jobs

    if [[ "$profile" == all ]]; then
        run_profile gcc
        run_profile clang
        run_profile sanitize
        run_profile release
    else
        run_profile "$profile"
    fi
}

main "$@"
