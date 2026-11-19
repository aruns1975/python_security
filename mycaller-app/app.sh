#!/usr/bin/env bash
# Start, stop, restart or inspect only mycaller-app. Delegates to ../manage.sh.
# Usage: ./app.sh {start|stop|restart|status|logs}
set -euo pipefail
[[ $# -eq 1 ]] || { echo "Usage: $0 {start|stop|restart|status|logs}" >&2; exit 2; }
exec "$(cd "$(dirname "$0")" && pwd)/../manage.sh" "$1" mycaller-app
