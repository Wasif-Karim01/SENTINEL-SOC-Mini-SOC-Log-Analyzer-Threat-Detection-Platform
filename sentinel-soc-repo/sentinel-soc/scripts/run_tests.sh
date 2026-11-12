#!/usr/bin/env bash
set -e
echo "Running SENTINEL SOC Automated Backend & E2E Test Suite..."
cd "$(dirname "$0")/../backend"
PYTHONPATH=. python3 tests/test_sentinel_soc.py
