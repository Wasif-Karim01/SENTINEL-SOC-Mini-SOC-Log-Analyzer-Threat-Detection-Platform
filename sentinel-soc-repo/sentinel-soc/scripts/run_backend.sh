#!/usr/bin/env bash
set -e
echo "Starting SENTINEL SOC Backend on http://127.0.0.1:8000 ..."
cd "$(dirname "$0")/../backend"
PYTHONPATH=. uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
