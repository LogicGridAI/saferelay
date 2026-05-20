#!/usr/bin/env bash
# Install safepaste to /usr/local/bin (Linux). Run from the directory containing safepaste.py.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/safepaste.py"
DEST="/usr/local/bin/safepaste"

if [[ ! -f "${SRC}" ]]; then
  echo "error: ${SRC} not found" >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "Installing to ${DEST} requires root; re-run with sudo." >&2
  exec sudo bash "$0" "$@"
fi

chmod 0755 "${SRC}"
ln -sf "${SRC}" "${DEST}"
echo "Linked ${DEST} -> ${SRC} (executable target). Use: safepaste < log.txt | ..."
echo "Config: ~/.safepaste/config.json  |  Vault: ~/.safepaste/vault.json"
