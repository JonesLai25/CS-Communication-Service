#!/bin/sh
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
[ "${CS_PHASE5_SCOPE:-}" = 1 ] || exec "$project/tools/phase5_scope.sh" "$project/tools/phase6_e2e_inner.sh"
cpu=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))'); taskset -pc "$cpu" "$$" >/dev/null
PYTHONPATH="$project/tools:$project/phase1" "$project/.venv/bin/python" -B -O -c 'from resource_guard import enforce; from exec_scope import test_slice; enforce(80*1024*1024,96*1024*1024,32,400000); test_slice() or exit(1)'
exec "$project/.venv/bin/python" -B -O "$project/phase6/test_installed_service.py"
