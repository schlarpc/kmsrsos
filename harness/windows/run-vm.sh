#!/usr/bin/env bash
# Boot the Windows 11 test VM (DISC-004, #146).
#
# AHCI + e1000e deliberately, not virtio: Windows has inbox drivers for both,
# so Setup finds the disk and the NIC with no driver injection step.
set -euo pipefail

VM=${KMSRSOS_VM_DIR:-$HOME/vm/win11}
ISO="${KMSRSOS_WIN_ISO:-}"

# The answer file lives on a removable USB stick; Windows Setup scans removable
# media roots for autounattend.xml. Passed only while UNATTEND=1 so that later
# boots do not re-trigger a pass.
UNATTEND_ARGS=()
if [[ "${UNATTEND:-0}" == "1" ]]; then
  UNATTEND_ARGS=(
    -drive "file=$VM/unattend.img,if=none,id=ua,format=raw"
    -device qemu-xhci,id=xhci
    -device usb-storage,bus=xhci.0,drive=ua,removable=on
  )
fi

CDROM_ARGS=()
if [[ "${WITHCD:-0}" == "1" ]]; then
  : "${ISO:?set KMSRSOS_WIN_ISO to the Windows ISO to boot the installer}"
  CDROM_ARGS=(
    -drive "file=$ISO,if=none,id=cd0,media=cdrom,readonly=on"
    -device ide-cd,bus=ahci.1,drive=cd0,bootindex=1
  )
fi

exec qemu-system-x86_64 \
  -name kmsrsos-win11 \
  -machine q35,accel=kvm \
  -cpu host \
  -smp 4 \
  -m 8192 \
  -rtc base=utc \
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=/run/libvirt/nix-ovmf/edk2-x86_64-code.fd" \
  -drive "if=pflash,format=qcow2,unit=1,file=$VM/OVMF_VARS.qcow2" \
  -device ich9-ahci,id=ahci \
  -drive "file=$VM/win11.qcow2,if=none,id=hd0,format=qcow2,cache=writeback,discard=unmap" \
  -device ide-hd,bus=ahci.0,drive=hd0,bootindex=2 \
  "${CDROM_ARGS[@]}" \
  "${UNATTEND_ARGS[@]}" \
  -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:13389-:3389${SLIRP_EXTRA:-}" \
  -device e1000e,netdev=n0 \
  -device VGA,vgamem_mb=32 \
  -display none \
  -monitor "unix:$VM/monitor.sock,server,nowait" \
  -serial "file:$VM/serial.log" \
  -D "$VM/qemu.log" \
  "$@"
