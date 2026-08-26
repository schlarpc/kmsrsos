#!/usr/bin/env bash
# Run one DISC-004 (#146) discovery scenario against the Windows guest.
#
#   scenario.sh <name> [key=value ...]
#
# Recognised keys, each an axis the issue names:
#   suffix=<domain|->        primary DNS suffix (registry, needs a reboot)
#   lookup=<domain|->        SoftwareProtectionPlatform\KeyManagementServiceLookupDomain
#   skms=<host|->            slmgr /skms, or /ckms to clear
#   reboot=yes               force a reboot before triggering
#   renew=yes                release/renew DHCP first (for the option 15 axis)
#
# The DHCP option 15 axis is not here: it is a QEMU netdev property, so it is
# selected by restarting the VM with DOMAINNAME= set (see run-matrix.sh).
#
# Every scenario starts from the `clean` snapshot, because SPP caches discovery
# results and backs off after a failure — reverting is the only way to make
# scenarios independent rather than order-dependent.
set -euo pipefail
VM=${KMSRSOS_VM_DIR:-$HOME/vm/win11}
cd "$VM"

NAME="$1"; shift
SUFFIX="-" ; LOOKUP="-" ; SKMS="-" ; FORCE_REBOOT="no" ; RENEW="no"
for kv in "$@"; do
  case "$kv" in
    suffix=*) SUFFIX="${kv#*=}" ;;
    lookup=*) LOOKUP="${kv#*=}" ;;
    skms=*)   SKMS="${kv#*=}" ;;
    reboot=*) FORCE_REBOOT="${kv#*=}" ;;
    renew=*)  RENEW="${kv#*=}" ;;
    *) echo "unknown key: $kv" >&2; exit 2 ;;
  esac
done

wait_ssh() {
  local n=0
  until ./win.sh 'hostname' >/dev/null 2>&1; do
    n=$((n+1)); [ "$n" -gt 60 ] && { echo "!! ssh never came back" >&2; return 1; }
    read -rt 5 <> <(:) || true
  done
}

echo "=== $NAME  (suffix=$SUFFIX lookup=$LOOKUP skms=$SKMS) ==="
./qm.sh "loadvm clean" >/dev/null
wait_ssh

# The snapshot predates this QEMU process, so its DHCP lease does too. Renew
# when the scenario depends on an option the current DHCP server is offering.
if [ "$RENEW" = "yes" ]; then
  ./win.sh 'ipconfig /release | Out-Null; ipconfig /renew | Out-Null' >/dev/null 2>&1 || true
  wait_ssh
fi

NEED_REBOOT="$FORCE_REBOOT"

if [ "$SUFFIX" != "-" ]; then
  ./win.sh "
    Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name 'Domain' -Value '$SUFFIX'
    Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name 'NV Domain' -Value '$SUFFIX'
  " >/dev/null
  NEED_REBOOT="yes"
fi

if [ "$LOOKUP" != "-" ]; then
  ./win.sh "
    Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform' -Name 'KeyManagementServiceLookupDomain' -Value '$LOOKUP'
  " >/dev/null
fi

if [ "$SKMS" != "-" ]; then
  ./win.sh "cscript //nologo C:\\Windows\\System32\\slmgr.vbs /skms $SKMS" >/dev/null 2>&1 || true
fi

if [ "$NEED_REBOOT" = "yes" ]; then
  ./win.sh 'Restart-Computer -Force' >/dev/null 2>&1 || true
  read -rt 15 <> <(:) || true
  wait_ssh
else
  # sppsvc reads the lookup domain at start-up, so bounce it rather than reboot.
  ./win.sh 'Stop-Service sppsvc -Force -ErrorAction SilentlyContinue' >/dev/null 2>&1 || true
fi

# Record the state actually in effect, not the state requested.
./win.sh '
  ipconfig /all | Select-String -Pattern "Primary Dns Suffix|Connection-specific"
  $spp = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" -ErrorAction SilentlyContinue
  "KMSLookupDomain=[" + $spp.KeyManagementServiceLookupDomain + "]"
  "KMSName=[" + $spp.KeyManagementServiceName + "]"
' > "captures/$NAME.state" 2>&1
sed 's/^/    /' "captures/$NAME.state"

PCAP="$VM/captures/$NAME.pcap"
rm -f "$PCAP"
./qm.sh "object_add filter-dump,id=cap,netdev=n0,file=$PCAP,maxlen=65536" >/dev/null

./win.sh 'cscript //nologo C:\Windows\System32\slmgr.vbs /ato' > "captures/$NAME.ato" 2>&1 || true
for i in $(seq 1 8); do read -rt 2 <> <(:) || true; done
./qm.sh "object_del cap" >/dev/null

echo "  /ato: $(grep -aoE '0x[0-9A-Fa-f]{8}|successfully' "captures/$NAME.ato" | head -1)"
python3 analyze.py "$PCAP" > "captures/$NAME.txt" 2>&1
sed -n '1,12p' "captures/$NAME.txt" | sed 's/^/    /'
