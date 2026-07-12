#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly root_dir="$(cd -- "$script_dir/.." && pwd -P)"
readonly private_key_pattern='-----BEGIN ([A-Z0-9]+ )*PRIVATE K[E]Y-----'
readonly credential_pattern='(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_live_[A-Za-z0-9]{16,})'
readonly local_home_pattern='/home/[A-Za-z0-9._-]+/'

declare -a candidates=()
failure=0

report_file() {
    printf 'publication check: refused path: %s\n' "$1" >&2
    failure=1
}

while IFS= read -r -d '' path; do
    candidates+=("$path")
done < <(git -C "$root_dir" ls-files --cached --others --exclude-standard -z)

if [[ ${#candidates[@]} -eq 0 ]]; then
    printf 'publication check: no candidate files found\n' >&2
    exit 2
fi

for path in "${candidates[@]}"; do
    case "/$path" in
        */build/*|*/.cache/*|*/__pycache__/*|*.pyc|*.pyo|*.pvlt|*.pvlt.lock|\
        *.pvault-recovery|*/.env|*/.env.*|*/core|*/core.*|*/vgcore.*|*/crash-*|\
        */leak-*|*/oom-*|*/timeout-*|*.tar.gz|*.pkg.tar.*)
            report_file "$path"
            ;;
    esac
    if [[ -L "$root_dir/$path" ]]; then
        report_file "$path (symbolic link requires explicit review)"
    fi
done

scan_pattern() {
    local description=$1
    local pattern=$2
    local match

    while IFS= read -r -d '' match; do
        printf 'publication check: %s in %s\n' "$description" "$match" >&2
        failure=1
    done < <(
        grep -EIlZ -- "$pattern" "${candidates[@]/#/$root_dir/}" 2>/dev/null || true
    )
}

scan_pattern 'private-key marker' "$private_key_pattern"
scan_pattern 'credential-shaped token' "$credential_pattern"
scan_pattern 'absolute user-home path' "$local_home_pattern"

if [[ "$failure" -ne 0 ]]; then
    printf 'publication check: FAILED (contents were not printed)\n' >&2
    exit 1
fi

printf 'publication check: %d candidate files passed\n' "${#candidates[@]}"
