#!/bin/sh
set -eu

# Optional acceleration must not prevent a direct compiler invocation.
if command -v sccache >/dev/null 2>&1; then
    cache_wrapper_dir=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && pwd -P)
    if [ -e "$cache_wrapper_dir/../.git" ] &&
        cache_git_common=$(/usr/bin/git -C "$cache_wrapper_dir/.." rev-parse --path-format=absolute --git-common-dir 2>/dev/null); then
        export SCCACHE_DIR="${SCCACHE_DIR:-$(/usr/bin/dirname "$cache_git_common")/.cache/sccache/objects}"
        export SCCACHE_SERVER_UDS="${SCCACHE_SERVER_UDS:-${SCCACHE_DIR}/server.sock}"
        export SCCACHE_CACHE_SIZE="${SCCACHE_CACHE_SIZE:-10G}"
        if mkdir -p "$SCCACHE_DIR"; then
            if sccache "$@"; then
                exit 0
            fi
            # sccache does not distinguish every infrastructure failure from
            # compiler errors. Retry once directly; preserve rustc's exit code.
            printf '%s\n' 'rustc-cache: sccache failed; retrying compiler directly' >&2
        fi
    fi
fi

exec "$@"
