#!/usr/bin/env bash
# secret-guard installer: symlink the CLI into ~/.local/bin.
# Zero dependencies beyond bash, coreutils, and python3.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="${SCRIPT_DIR}/secret_guard.py"
BIN_DIR="${HOME}/.local/bin"
TARGET="${BIN_DIR}/secret-guard"

if ! command -v python3 >/dev/null 2>&1; then
  echo "secret-guard: python3 is required but was not found on PATH." >&2
  exit 1
fi

if [ ! -f "${SOURCE}" ]; then
  echo "secret-guard: could not find ${SOURCE}" >&2
  exit 1
fi

mkdir -p "${BIN_DIR}"
chmod 755 "${SOURCE}"
ln -sfn "${SOURCE}" "${TARGET}"

echo "secret-guard: installed ${TARGET} -> ${SOURCE}"

case ":${PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *)
    echo "secret-guard: add ${BIN_DIR} to PATH, for example:" >&2
    echo '  export PATH="$HOME/.local/bin:$PATH"' >&2
    ;;
esac

if [ "${1:-}" = "--hook" ]; then
  "${TARGET}" install
fi

echo "Next: run 'secret-guard install' inside a Git repository."
