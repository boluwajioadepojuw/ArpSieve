# LinkSentry


A lightweight Python-based ARP spoofing detection tool. Monitors ARP traffic on the local network segment
and alerts when ARP cache poisoning or man-in-the-middle attacks are detected.

## Features
- Real-time ARP packet monitoring (live interface sniffing)
- Offline PCAP analysis (`-f/--pcap`) for incident review or testing
- Detection of ARP spoofing/poisoning attacks
- MAC-to-IP mapping verification
- Console and log file alerting

## How It Works
LinkSentry captures ARP packets on the local network interface and maintains a table
of known MAC-to-IP mappings. When a conflicting ARP announcement is detected (two
different MAC addresses claiming the same IP), an alert is raised indicating a
potential ARP spoofing attack in progress.

## Usage
```bash
# Live monitoring (requires root / CAP_NET_RAW):
sudo python3 arp_sentinel.py -i eth0

# Offline analysis of a capture (no root needed):
python3 arp_sentinel.py -f capture.pcap
```

## Stack
- Python 3.x
- scapy
- Standard library (argparse, logging)

## Author

Boluwaji Oluwaseyi Adepoju


## Test captures

`samples/` contains two ARP captures used to validate detection:

- `benign.pcap` -- normal ARP traffic (no alert expected)
- `poisoned.pcap` -- an ARP cache-poisoning attempt; running the tool on it raises a
  man-in-the-middle alert

```bash
python3 arp_sentinel.py -f samples/poisoned.pcap
```
