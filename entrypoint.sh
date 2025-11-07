#!/usr/bin/env bash
set -euo pipefail

: "${CACHE_DIR:=/app/.cache}"
mkdir -p "$CACHE_DIR"

if [ ! -w "$CACHE_DIR" ]; then
  echo "[entrypoint] Cache dir $CACHE_DIR not writable" >&2
  exit 1
fi

exec "$@"
