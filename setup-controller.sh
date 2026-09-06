#!/bin/bash
# Create the Ansible controller venv and install Galaxy collections.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

if ! command -v uv >/dev/null 2>&1; then
  echo "error: uv is required. See https://docs.astral.sh/uv/getting-started/installation/" >&2
  exit 1
fi

uv sync
uv run ansible-galaxy collection install -r requirements.yml

cat <<EOF
Controller ready.

Examples:
  uv run ansible -m ping secure_vps
  uv run ansible-playbook site.yml --ask-vault-pass -e firewall_lockdown_confirm=false
  uv run ansible-vault encrypt group_vars/all/vault.yml
EOF
