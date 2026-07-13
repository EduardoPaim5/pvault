#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly root_dir="$(cd -- "$script_dir/.." && pwd -P)"

[[ -x /usr/bin/python3 ]] || {
    printf 'external-restore-run: required executable not found: /usr/bin/python3\n' >&2
    exit 2
}
/usr/bin/python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' || {
    printf 'external-restore-run: Python 3.10 or newer is required\n' >&2
    exit 2
}

exec /usr/bin/python3 "$root_dir/tests/manual/external_restore_protocol.py" run "$@"
