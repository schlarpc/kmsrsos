#!/usr/bin/env python3
"""Summarise what a Windows client asked for during a discovery scenario.

`DISC-004` (#146). Reads a pcap produced by QEMU's filter-dump and reports the
name-resolution attempts in order, so a scenario can be judged on what the
client *asked*, independent of whether anything answered.

Usage: analyze.py <scenario.pcap> [--json]
"""
import json
import sys
from collections import Counter

from scapy.all import DNS, IP, IPv6, TCP, UDP, rdpcap

MDNS_ADDR = ("224.0.0.251", "ff02::fb")
LLMNR_ADDR = ("224.0.0.252", "ff02::1:3")
QTYPE = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT",
         28: "AAAA", 33: "SRV", 255: "ANY"}


def addr_of(pkt, field):
    """Source or destination address, whichever IP version carries it."""
    for layer in (IP, IPv6):
        if layer in pkt:
            return getattr(pkt[layer], field)
    return ""


def channel(pkt):
    """Which resolution mechanism a packet belongs to, or None."""
    if UDP in pkt:
        dport, sport = pkt[UDP].dport, pkt[UDP].sport
        dst = addr_of(pkt, "dst")
        if dport == 5353 or sport == 5353:
            return "mDNS" if dst in MDNS_ADDR or sport == 5353 else "mDNS-unicast"
        if dport == 5355 or sport == 5355:
            return "LLMNR"
        if dport == 137 or sport == 137:
            return "NBNS"
        if dport == 53 or sport == 53:
            return "DNS/udp"
    if TCP in pkt:
        if pkt[TCP].dport == 53 or pkt[TCP].sport == 53:
            return "DNS/tcp"
        if pkt[TCP].dport == 1688:
            return "KMS/1688"
    return None


def main():
    path = sys.argv[1]
    as_json = "--json" in sys.argv
    packets = rdpcap(path)
    t0 = packets[0].time if packets else 0

    events, kms, channels = [], [], Counter()
    for pkt in packets:
        chan = channel(pkt)
        if chan is None:
            continue
        channels[chan] += 1
        offset = round(float(pkt.time - t0), 3)

        if chan == "KMS/1688":
            if pkt[TCP].flags == "S":
                kms.append({"t": offset, "dst": addr_of(pkt, "dst")})
            continue

        if DNS not in pkt:
            continue
        dns = pkt[DNS]
        # Questions only: this measures what the client asked for.
        if dns.qr != 0 or not dns.qdcount:
            continue
        for i in range(dns.qdcount):
            try:
                q = dns.qd[i]
            except (IndexError, TypeError):
                break
            events.append({
                "t": offset,
                "channel": chan,
                "name": q.qname.decode(errors="replace").rstrip("."),
                "type": QTYPE.get(q.qtype, str(q.qtype)),
                "dst": addr_of(pkt, "dst"),
            })

    vlmcs = [e for e in events if "_vlmcs" in e["name"].lower()]
    report = {
        "pcap": path,
        "packets": len(packets),
        "channels": dict(channels),
        "vlmcs_queries": vlmcs,
        "kms_connections": kms,
        "all_queries": events,
    }

    if as_json:
        print(json.dumps(report, indent=2))
        return

    print(f"{path}: {len(packets)} packets  channels={dict(channels)}")
    print(f"\n_vlmcs queries ({len(vlmcs)}):")
    if not vlmcs:
        print("  (none)")
    for e in vlmcs:
        print(f"  {e['t']:8.3f}  {e['channel']:<13} {e['type']:<5} {e['name']}  -> {e['dst']}")
    print(f"\nTCP connections to 1688 ({len(kms)}):")
    for c in kms:
        print(f"  {c['t']:8.3f}  -> {c['dst']}")
    other = [e for e in events if "_vlmcs" not in e["name"].lower()]
    print(f"\nother queries ({len(other)}), first 25:")
    for e in other[:25]:
        print(f"  {e['t']:8.3f}  {e['channel']:<13} {e['type']:<5} {e['name']}")


if __name__ == "__main__":
    main()
