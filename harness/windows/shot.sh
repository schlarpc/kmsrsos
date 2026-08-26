#!/usr/bin/env bash
# Grab the VM framebuffer as a PNG. Usage: shot.sh [name]
set -euo pipefail
VM=${KMSRSOS_VM_DIR:-$HOME/vm/win11}
NAME="${1:-shot}"
rm -f "$VM/$NAME.ppm" "$VM/$NAME.png"
"$VM/qm.sh" "screendump $VM/$NAME.ppm" >/dev/null
for _ in $(seq 1 40); do
  [[ -s "$VM/$NAME.ppm" ]] && break
  read -rt 0.25 <> <(:) || true
done
magick "$VM/$NAME.ppm" -resize '1280x1280>' "$VM/$NAME.png"
rm -f "$VM/$NAME.ppm"
echo "$VM/$NAME.png"
