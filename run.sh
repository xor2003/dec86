#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS_CONFIG="${HARNESS_CONFIG:-${ROOT_DIR}/.codex_harness.conf}"
PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"

if [[ -f "${HARNESS_CONFIG}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${HARNESS_CONFIG}"
  set +a
fi

export ROOT_DIR
export HARNESS_CONFIG
export PYTHON_BIN

exec "${PYTHON_BIN}" -m meta_harness "$@"
