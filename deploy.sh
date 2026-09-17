#!/usr/bin/env bash
# Build and (re)start with the git version baked in; plain `docker compose up --build` shows "unknown".
set -euo pipefail
cd "$(dirname "$0")"

APP_VERSION="$(git describe --always --dirty 2>/dev/null || echo unknown)"
APP_BUILT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export APP_VERSION APP_BUILT

docker compose up -d --build "$@"
echo "mikrotik-agent ${APP_VERSION} (built ${APP_BUILT})"
