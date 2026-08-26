#!/usr/bin/env bash
# Build the Windows 11 measurement VM from an ISO (`DISC-004`, #146).
#
#   KMSRSOS_WIN_ISO=/path/to/windows.iso ./setup.sh
#
# Installs unattended and ends with a `clean` VM snapshot that every scenario
# reverts to. Nothing here needs root: QEMU's user-mode networking, filter-dump
# captures and internal snapshots replace the tap device, tcpdump and external
# storage that this would otherwise want.
#
# Deliberate choices worth not re-litigating:
#   * AHCI and e1000e, not virtio — Windows has inbox drivers for both, so
#     Setup finds the disk and the NIC with no driver injection step.
#   * TPM and Secure Boot are bypassed in the answer file rather than emulated,
#     because swtpm is not a dependency this harness is worth acquiring.
#   * The answer file is delivered on a FAT image attached as removable USB,
#     built with mtools, so no ISO authoring tool is needed either.
set -euo pipefail

VM="${KMSRSOS_VM_DIR:-$HOME/vm/win11}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ISO="${KMSRSOS_WIN_ISO:?set KMSRSOS_WIN_ISO to the Windows 11 ISO}"
IMAGE_INDEX="${KMSRSOS_WIN_IMAGE_INDEX:-3}"

for tool in qemu-system-x86_64 qemu-img mkfs.vfat mcopy socat magick ssh-keygen; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

OVMF_CODE="${KMSRSOS_OVMF_CODE:-/run/libvirt/nix-ovmf/edk2-x86_64-code.fd}"
OVMF_VARS="${KMSRSOS_OVMF_VARS:-/run/libvirt/nix-ovmf/edk2-i386-vars.fd}"
[ -r "$OVMF_CODE" ] || { echo "no OVMF firmware at $OVMF_CODE" >&2; exit 1; }

mkdir -p "$VM"
cd "$VM"

[ -f id_vm ] || ssh-keygen -t ed25519 -N '' -C kmsrsos-vm -f id_vm >/dev/null

sed "s|@@SSH_PUBLIC_KEY@@|$(cat id_vm.pub)|" "$HERE/autounattend.xml.in" > autounattend.xml
python3 -c "import xml.dom.minidom,sys; xml.dom.minidom.parse('autounattend.xml')"
if [ "$IMAGE_INDEX" != "3" ]; then
  sed -i "s|<Value>3</Value>|<Value>$IMAGE_INDEX</Value>|" autounattend.xml
fi

dd if=/dev/zero of=unattend.img bs=1M count=8 status=none
mkfs.vfat -n UNATTEND unattend.img >/dev/null
MTOOLS_SKIP_CHECK=1 mcopy -i unattend.img autounattend.xml ::/autounattend.xml

qemu-img create -f qcow2 win11.qcow2 "${KMSRSOS_VM_DISK:-64G}" >/dev/null
# pflash vars must be qcow2, or `savevm` refuses: a raw writable device cannot
# hold a snapshot and the whole scenario model depends on snapshots.
qemu-img convert -O qcow2 "$OVMF_VARS" OVMF_VARS.qcow2

echo "booting installer; this takes 20-40 minutes"
rm -f monitor.sock
UNATTEND=1 WITHCD=1 nohup "$HERE/run-vm.sh" > vm-stdout.log 2>&1 &
disown

for _ in $(seq 1 60); do [ -S monitor.sock ] && break; read -rt 0.5 <> <(:) || true; done
[ -S monitor.sock ] || { echo "QEMU never started" >&2; tail -20 vm-stdout.log >&2; exit 1; }

# "Press any key to boot from CD or DVD" has a short window and no key means
# the firmware falls through to the empty disk.
for _ in $(seq 1 40); do "$HERE/qm.sh" "sendkey ret" >/dev/null 2>&1 || true; read -rt 0.5 <> <(:) || true; done

echo "waiting for the guest to finish installing and answer SSH"
n=0
until "$HERE/win.sh" 'hostname' >/dev/null 2>&1; do
  n=$((n+1))
  [ "$n" -gt 360 ] && { echo "guest never came up" >&2; exit 1; }
  # Keep the display awake so a screenshot is diagnostic if this fails.
  "$HERE/qm.sh" "sendkey shift" >/dev/null 2>&1 || true
  read -rt 10 <> <(:) || true
done

"$HERE/win.sh" '
  powercfg /change monitor-timeout-ac 0
  powercfg /change standby-timeout-ac 0
  powercfg /change hibernate-timeout-ac 0
  Set-Service wuauserv -StartupType Disabled
  Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
' >/dev/null 2>&1 || true

"$HERE/qm.sh" "eject -f cd0" >/dev/null 2>&1 || true
"$HERE/qm.sh" "savevm clean" >/dev/null

echo "done. snapshot 'clean' taken:"
"$HERE/qm.sh" "info snapshots"
