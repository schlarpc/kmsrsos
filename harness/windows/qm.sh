#!/usr/bin/env bash
# Talk to the running VM's QEMU monitor. Usage: qm.sh "<monitor command>"
# The monitor echoes each character as it is typed; only the text after the
# final echo of the command is real output.
set -euo pipefail
printf '%s\n' "$*" | socat -t 5 - "unix-connect:${KMSRSOS_VM_DIR:-$HOME/vm/win11}/monitor.sock" 2>/dev/null \
  | sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g' -e 's/\r/\n/g' \
  | grep -vE '^\(qemu\)|^QEMU [0-9]|^$' \
  | grep -vFx "$*" || true
