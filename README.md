# ArpSieve

[![CI](https://github.com/boluwajioadepojuw/ArpSieve/actions/workflows/ci.yml/badge.svg)](https://github.com/boluwajioadepojuw/ArpSieve/actions/workflows/ci.yml)

A small Python tool that watches ARP traffic on the local network
segment and alerts when something claims an IP address that already
belongs to another MAC. That is the signature of an ARP cache poisoning
or man-in-the-middle attack.

## What it does

- Real-time ARP monitoring on a live interface
- Offline PCAP analysis (`-f/--pcap`) for incident review or testing
- ARP spoofing/poisoning detection
- MAC-to-IP mapping verification
- Alerts to console and log file

## How it works

ArpSieve captures ARP packets on the local interface and keeps a table
of known MAC-to-IP mappings. When a conflicting ARP announcement shows
up (two different MAC addresses claiming the same IP), it raises a
man-in-the-middle alert.

## Install

```bash
pip install -r requirements.txt    # installs scapy
```

## Usage

```bash
# Live monitoring (requires root / CAP_NET_RAW):
sudo python3 arp_sieve.py -i eth0

# Offline analysis of a capture (no root needed):
python3 arp_sieve.py -f capture.pcap
```

## Stack

- Python 3.x
- scapy
- Standard library (argparse, logging)

## Author

Boluwaji Oluwaseyi Adepoju

## Test captures

`samples/` has two ARP captures used to validate detection:

- `benign.pcap`: normal ARP traffic, no alert expected
- `poisoned.pcap`: an ARP cache-poisoning attempt. Running the tool on
  it raises the man-in-the-middle alert.

```bash
python3 arp_sieve.py -f samples/poisoned.pcap
```

The same captures back the pytest suite in `tests/` (CI runs them on
Python 3.11 and 3.12):

```bash
pip install pytest
python -m pytest -q
```

## Screenshot

Real alert on the poisoned capture:

![ArpSieve alert](screenshots/arpsieve-alert.png)

## Related projects

Part of the same home-SOC stack:

- [SOCAtelier](https://github.com/boluwajioadepojuw/SOCAtelier) - the lab console and detection engine this tool can feed
- [DomainSieve](https://github.com/boluwajioadepojuw/DomainSieve) - gateway rules from newly registered domains
- [IocVerdict](https://github.com/boluwajioadepojuw/IocVerdict) - IOC enrichment for the indicators these alerts surface
- [SigScope](https://github.com/boluwajioadepojuw/SigScope) - ATT&CK coverage gate for the Sigma rules behind the detections
- [SplunkHarbor](https://github.com/boluwajioadepojuw/SplunkHarbor) - Splunk ingestion lab for the same telemetry

## Flow

```mermaid
flowchart TD
    A[sniff ARP packets - live or pcap] --> B[track IP to MAC mapping]
    B --> C{new claim conflicts with known MAC?}
    C -->|yes| D[ALERT: possible ARP spoofing]
    C -->|no| E[update mapping]
```
