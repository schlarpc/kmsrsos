#!/usr/bin/env bash
# Restart the VM with a different SLIRP configuration (`DISC-004`, #146).
#
# The DHCP option 15 axis cannot be changed on a live guest: the domain name is
# a property of QEMU's DHCP server, so it is selected here and the guest is
# made to renew its lease afterwards.
#
#   restart-vm.sh                       # no DHCP domain name
#   restart-vm.sh dhcp.example          # DHCP option 15 = dhcp.example
set -euo pipefail
VM=${KMSRSOS_VM_DIR:-$HOME/vm/win11}
cd "$VM"

DOMAIN="${1:-}"
export SLIRP_EXTRA=""
[ -n "$DOMAIN" ] && SLIRP_EXTRA=",domainname=$DOMAIN"

if pgrep -f "qemu-system.*kmsrsos-win11" >/dev/null; then
  ./qm.sh "quit" >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    pgrep -f "qemu-system.*kmsrsos-win11" >/dev/null || break
    read -rt 1 <> <(:) || true
  done
fi
rm -f monitor.sock
nohup ./run-vm.sh > vm-stdout.log 2>&1 &
disown

for _ in $(seq 1 60); do [ -S monitor.sock ] && break; read -rt 0.5 <> <(:) || true; done
[ -S monitor.sock ] || { echo "monitor never appeared"; tail -5 vm-stdout.log; exit 1; }

# Start from the known-good state rather than a cold boot.
./qm.sh "loadvm clean" >/dev/null
n=0
until ./win.sh 'hostname' >/dev/null 2>&1; do
  n=$((n+1)); [ "$n" -gt 60 ] && { echo "ssh never came back"; exit 1; }
  read -rt 5 <> <(:) || true
done

# The restored lease predates this QEMU process; renew so option 15 applies.
./win.sh 'ipconfig /release | Out-Null; ipconfig /renew | Out-Null' >/dev/null 2>&1 || true
n=0
until ./win.sh 'hostname' >/dev/null 2>&1; do
  n=$((n+1)); [ "$n" -gt 30 ] && break
  read -rt 3 <> <(:) || true
done

echo "VM up with DHCP domain=[${DOMAIN:-<unset>}]"
./win.sh 'ipconfig /all | Select-String -Pattern "Primary Dns Suffix|Connection-specific|IPv4 Address"' 2>&1 | sed 's/^/    /'
