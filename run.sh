#!/usr/bin/env bash
# Sherlock launcher - always uses a Python interpreter that has Flask.
set -euo pipefail

cd "$(dirname "$0")"

# Ignore empty or 0 PORT values (some environments set PORT=0 meaning "random").
if [ -z "${PORT:-}" ] || [ "${PORT:-}" = "0" ]; then
  PORT=5000
fi

# Prefer the project venv, then any python3 that can import flask.
if [ -x ".venv/bin/python" ] && .venv/bin/python -c "import flask" >/dev/null 2>&1; then
  PY=".venv/bin/python"
else
  PY=""
  for cand in python3 /usr/bin/python3 /usr/local/bin/python3 python3.14 python3.13 python3.12 python3.11 python3.10 python3.9; do
    if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "import flask" >/dev/null 2>&1; then
      PY="$cand"
      break
    fi
  done
fi

if [ -z "$PY" ]; then
  echo "No Python with Flask found. Creating .venv ..."
  python3 -m venv .venv
  .venv/bin/python -m pip install --quiet flask flask-cors
  PY=".venv/bin/python"
fi

echo "Sherlock starting with $PY on port $PORT"
exec env PORT="$PORT" "$PY" app.py
