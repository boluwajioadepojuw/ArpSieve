#!/usr/bin/env python3
"""LinkSentry -- ARP Spoofing Detection Tool.

Monitors ARP traffic on the local network segment and alerts when ARP cache
poisoning or man-in-the-middle attacks are detected. Maintains a table of
known MAC-to-IP mappings; when two different MAC addresses claim the same IP,
an alert is raised.

Modes:
  * live sniffing on a network interface (-i/--interface)
  * offline analysis of a PCAP capture (-f/--pcap), useful for incident
    review or testing without root privileges

Stack: Python 3.x, scapy, standard library (argparse, logging).
"""

import argparse
import logging
import sys
import time
from collections import defaultdict

from scapy.all import ARP, Ether, rdpcap, sniff

LOG = logging.getLogger("arpsentinel")


class ArpMonitor:
    """Tracks observed IP->MAC bindings and flags conflicting claims."""

    def __init__(self):
        # ip -> set of MACs that have claimed it
        self.claims = defaultdict(set)
        # (ip, mac) -> first-seen timestamp
        self.first_seen = {}

    def feed(self, pkt):
        """Process one ARP packet. Returns an alert string or None."""
        if not (pkt.haslayer(ARP) and pkt.haslayer(Ether)):
            return None
        arp = pkt[ARP]
        # Only wire-format Ethernet/IPv4 ARP is meaningful here.
        if arp.hwtype != 1 or arp.ptype != 0x0800 or arp.op not in (1, 2):
            return None
        ip = arp.psrc
        mac = arp.hwsrc
        if not ip or not mac or ip == "0.0.0.0" or mac == "00:00:00:00:00:00":
            return None

        key = (ip, mac)
        if key not in self.first_seen:
            self.first_seen[key] = time.time()

        self.claims[ip].add(mac)
        if len(self.claims[ip]) > 1:
            known = ", ".join(sorted(self.claims[ip]))
            return (
                f"[ALERT] Possible ARP spoofing: IP {ip} claimed by "
                f"multiple MACs -> {known} "
                f"(new claim from {mac})"
            )
        return None

    def summary(self):
        return {ip: sorted(macs) for ip, macs in self.claims.items()}


def analyze_pcap(path, monitor):
    """Replay a PCAP through the monitor and return the list of alerts."""
    alerts = []
    try:
        packets = rdpcap(path)
    except Exception as exc:  # scapy raises a variety of IO/format errors
        LOG.error("failed to read pcap %s: %s", path, exc)
        return alerts
    for pkt in packets:
        alert = monitor.feed(pkt)
        if alert:
            alerts.append(alert)
    LOG.info("analyzed %d packets from %s", len(packets), path)
    return alerts


def main():
    parser = argparse.ArgumentParser(
        description="Detect ARP spoofing / cache-poisoning attacks."
    )
    parser.add_argument(
        "-i", "--interface", help="network interface to sniff on (live mode)"
    )
    parser.add_argument(
        "-f", "--pcap", help="analyze an offline PCAP file instead of sniffing"
    )
    parser.add_argument(
        "-l", "--log", default="arpsentinel.log",
        help="log file to write alerts to (default: arpsentinel.log)"
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="stop after N packets (live mode only; 0 = run forever)"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(args.log, encoding="utf-8"),
        ],
    )
    LOG.info("LinkSentry started (mode=%s)", "pcap" if args.pcap else "live")
    if args.pcap:
        if args.interface:
            parser.error("--interface and --pcap are mutually exclusive")
        alerts = analyze_pcap(args.pcap, ArpMonitor())
    else:
        iface = args.interface or "eth0"
        monitor = ArpMonitor()
        LOG.info("sniffing on interface %s (ctrl-c to stop)", iface)
        try:
            sniff(
                iface=iface,
                filter="arp",
                prn=lambda p: (
                    (lambda a: LOG.warning(a) if a else None)(monitor.feed(p))
                ),
                store=False,
                count=args.count or None,
            )
        except PermissionError:
            LOG.error("live sniffing requires root/CAP_NET_RAW; "
                      "use --pcap for offline analysis")
            return 2
        except KeyboardInterrupt:
            LOG.info("stopped by user")
        alerts = []

    for alert in alerts:
        LOG.warning(alert)
    LOG.info("LinkSentry finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
