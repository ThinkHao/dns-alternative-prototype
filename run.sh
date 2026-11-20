#!/bin/sh
set -eu

APP_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
if [ -x "$APP_DIR/.venv/bin/python" ]; then
    PYTHON_BIN="$APP_DIR/.venv/bin/python"
else
    PYTHON_BIN=${PYTHON:-python3}
fi

if ! "$PYTHON_BIN" -c 'import sys, dns; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
    printf '%s\n' '需要 Python 3.11+ 并安装依赖。运行：python3 -m pip install -r requirements.txt' >&2
    exit 1
fi

exec "$PYTHON_BIN" "$APP_DIR/server.py"
