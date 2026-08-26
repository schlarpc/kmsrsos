#!/usr/bin/env bash
# Run a PowerShell command in the guest over SSH. Usage: win.sh '<powershell>'
set -euo pipefail
exec ssh -q \
  -i ${KMSRSOS_VM_DIR:-$HOME/vm/win11}/id_vm \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR \
  -o ConnectTimeout=10 \
  -p 2222 kms@127.0.0.1 "$@"
