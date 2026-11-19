#!/usr/bin/env bash
# Start all three sample apps on 127.0.0.1 (local development only).
#
#   mycaller-app        58081   inbound: API key           outbound: CALLED_APP (API key), ANOTHER_CALLED_APP (app credentials)
#   called-app          48081   inbound: API key
#   another-called-app  38081   inbound: application ID + secret key
#
# Prerequisite: python3 scripts/generate_credentials.py
# Each app's .env is exported into that app's process only, so secrets never cross apps.
# Logs: .run/<app>.log. Ctrl-C (or SIGTERM) stops all three.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
UV="${UV:-$(command -v uv || echo /opt/homebrew/bin/uv)}"
mkdir -p "$ROOT/.run"

APPS=("called-app:48081" "another-called-app:38081" "mycaller-app:58081")

for entry in "${APPS[@]}"; do
  app="${entry%%:*}"
  if [[ ! -f "$ROOT/$app/.env" ]]; then
    echo "Missing $app/.env - run: python3 scripts/generate_credentials.py" >&2
    exit 1
  fi
done

pids=()
cleanup() {
  trap - INT TERM EXIT
  for pid in "${pids[@]:-}"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  echo "All apps stopped."
}
trap cleanup INT TERM EXIT

for entry in "${APPS[@]}"; do
  app="${entry%%:*}"
  port="${entry##*:}"
  (
    cd "$ROOT/$app"
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
    exec "$UV" run --quiet uvicorn --factory main:create_app --host 127.0.0.1 --port "$port"
  ) >"$ROOT/.run/$app.log" 2>&1 &
  pids+=("$!")
  echo "Started $app on http://127.0.0.1:$port (log: .run/$app.log)"
done

wait
