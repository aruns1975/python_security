#!/usr/bin/env bash
# Start, stop, restart and inspect the sample apps in the background (local development only).
#
# Usage: ./manage.sh {start|stop|restart|status|logs} [all|mycaller-app|called-app|another-called-app]
#
#   mycaller-app        58081   calls called-app and another-called-app
#   called-app          48081
#   another-called-app  38081
#
# - Target defaults to "all". "all" starts the downstream apps first and stops mycaller-app first.
# - Each app's .env is exported into that app's process only; secrets never cross apps or hit the
#   command line. Prerequisite: python3 scripts/generate_credentials.py
# - PID files and logs: .run/<app>.pid, .run/<app>.log
# - start waits for GET /health to answer; stop sends SIGTERM, then SIGKILL after a grace period.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
RUN_DIR="$ROOT/.run"
HOST="127.0.0.1"
START_TIMEOUT="${START_TIMEOUT:-20}"   # seconds to wait for /health
STOP_TIMEOUT="${STOP_TIMEOUT:-10}"     # seconds before SIGKILL
ALL_APPS=(called-app another-called-app mycaller-app)   # start order

port_of() {
  case "$1" in
    mycaller-app) echo 58081 ;;
    called-app) echo 48081 ;;
    another-called-app) echo 38081 ;;
    *) return 1 ;;
  esac
}

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

pid_file() { echo "$RUN_DIR/$1.pid"; }
log_file() { echo "$RUN_DIR/$1.log"; }

# Prints the PID if the app is running (and the PID really is our uvicorn), else nothing.
running_pid() {
  local file pid
  file="$(pid_file "$1")"
  [[ -f "$file" ]] || return 0
  pid="$(cat "$file")"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && ps -p "$pid" -o command= | grep -q "uvicorn"; then
    echo "$pid"
  else
    rm -f "$file"   # stale
  fi
}

port_in_use() { lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

healthy() { curl -fs -o /dev/null --max-time 2 "http://$HOST:$1/health"; }

start_app() {
  local app="$1" port pid
  port="$(port_of "$app")"
  pid="$(running_pid "$app")"
  if [[ -n "$pid" ]]; then
    echo "$app: already running (pid $pid, port $port)"
    return 0
  fi
  if [[ ! -f "$ROOT/$app/.env" ]]; then
    echo "$app: missing $app/.env - run: python3 scripts/generate_credentials.py" >&2
    return 1
  fi
  if port_in_use "$port"; then
    echo "$app: port $port is already in use by another process" >&2
    return 1
  fi

  mkdir -p "$RUN_DIR"
  (
    cd "$ROOT/$app"
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
    # Prefer the app's venv directly so the PID we record is uvicorn itself.
    if [[ -x .venv/bin/python ]]; then
      exec .venv/bin/python -m uvicorn --factory main:create_app --host "$HOST" --port "$port"
    fi
    exec "${UV:-$(command -v uv || echo /opt/homebrew/bin/uv)}" run --quiet \
      uvicorn --factory main:create_app --host "$HOST" --port "$port"
  ) </dev/null >>"$(log_file "$app")" 2>&1 &
  pid=$!
  echo "$pid" >"$(pid_file "$app")"

  local waited=0
  until healthy "$port"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$(pid_file "$app")"
      echo "$app: failed to start - last log lines:" >&2
      tail -n 15 "$(log_file "$app")" >&2
      return 1
    fi
    if (( waited >= START_TIMEOUT )); then
      echo "$app: no healthy response after ${START_TIMEOUT}s; stopping it" >&2
      stop_app "$app" >/dev/null
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  echo "$app: started (pid $pid) http://$HOST:$port  log: .run/$app.log"
}

stop_app() {
  local app="$1" pid waited=0
  pid="$(running_pid "$app")"
  if [[ -z "$pid" ]]; then
    echo "$app: not running"
    return 0
  fi
  kill -TERM "$pid" 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null; do
    if (( waited >= STOP_TIMEOUT )); then
      echo "$app: did not stop after ${STOP_TIMEOUT}s; sending SIGKILL" >&2
      kill -KILL "$pid" 2>/dev/null || true
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  rm -f "$(pid_file "$app")"
  echo "$app: stopped"
}

status_app() {
  local app="$1" port pid health
  port="$(port_of "$app")"
  pid="$(running_pid "$app")"
  if [[ -z "$pid" ]]; then
    printf '%-20s %-8s port %-6s %s\n' "$app" "stopped" "$port" ""
    return 0
  fi
  if healthy "$port"; then health="healthy"; else health="not responding"; fi
  printf '%-20s %-8s port %-6s pid %-7s %s\n' "$app" "running" "$port" "$pid" "$health"
}

logs_app() {
  local file
  file="$(log_file "$1")"
  [[ -f "$file" ]] || { echo "$1: no log yet"; return 0; }
  echo "==> .run/$1.log <=="
  tail -n "${LINES:-30}" "$file"
}

# Resolve target(s) in the order the command needs.
targets() {
  local target="$1" order="$2"
  if [[ "$target" == "all" ]]; then
    if [[ "$order" == "reverse" ]]; then
      echo "mycaller-app another-called-app called-app"
    else
      echo "${ALL_APPS[*]}"
    fi
  elif port_of "$target" >/dev/null; then
    echo "$target"
  else
    echo "Unknown app: $target" >&2
    usage
  fi
}

[[ $# -ge 1 && $# -le 2 ]] || usage
command="$1"
target="${2:-all}"
rc=0

case "$command" in
  start)
    for app in $(targets "$target" forward); do start_app "$app" || rc=1; done
    ;;
  stop)
    for app in $(targets "$target" reverse); do stop_app "$app" || rc=1; done
    ;;
  restart)
    for app in $(targets "$target" reverse); do stop_app "$app" || rc=1; done
    for app in $(targets "$target" forward); do start_app "$app" || rc=1; done
    ;;
  status)
    for app in $(targets "$target" forward); do status_app "$app"; done
    ;;
  logs)
    for app in $(targets "$target" forward); do logs_app "$app"; done
    ;;
  *)
    usage
    ;;
esac
exit "$rc"
