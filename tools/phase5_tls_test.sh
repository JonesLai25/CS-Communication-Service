#!/bin/sh
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
[ "$(id -u)" -ne 0 ] || exit 1
available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
[ -n "$available" ] && [ "$available" -ge 400000 ] || exit 1
if [ "${CS_PHASE5_SCOPE:-}" != 1 ]; then exec "$project/tools/phase5_scope.sh" "$project/tools/phase5_tls_test.sh"; fi
cpu=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))'); taskset -pc "$cpu" "$$" >/dev/null
PYTHONPATH="$project/tools:$project/phase1" "$project/.venv/bin/python" -B -O -c 'from resource_guard import enforce; from exec_scope import test_slice; enforce(80*1024*1024,96*1024*1024,32,400000); test_slice() or exit(1)'
exec "$project/.venv/bin/python" -B -O "$project/phase5/test_exec_tls.py"
