"""ArpSieve detection tests.

Two layers:

- unit tests build ARP packets with scapy and drive ArpMonitor.feed()
- integration tests replay the sample captures in samples/ (benign: no
  alert expected, poisoned: at least one alert)
"""

from pathlib import Path

from scapy.all import ARP, Ether

import arp_sieve

ROOT = Path(__file__).resolve().parents[1]


def _arp(ip_src, mac_src, op=1, ip_dst="10.0.0.2"):
    return Ether(src=mac_src, dst="ff:ff:ff:ff:ff:ff") / ARP(
        hwtype=1,
        ptype=0x0800,
        hwlen=6,
        plen=4,
        op=op,
        hwsrc=mac_src,
        psrc=ip_src,
        hwdst="00:00:00:00:00:00",
        pdst=ip_dst,
    )


def test_single_claim_no_alert():
    m = arp_sieve.ArpMonitor()
    assert m.feed(_arp("10.0.0.1", "aa:bb:cc:dd:ee:01")) is None


def test_repeated_same_claim_no_alert():
    m = arp_sieve.ArpMonitor()
    m.feed(_arp("10.0.0.1", "aa:bb:cc:dd:ee:01"))
    assert m.feed(_arp("10.0.0.1", "aa:bb:cc:dd:ee:01")) is None


def test_conflicting_mac_raises_alert():
    m = arp_sieve.ArpMonitor()
    m.feed(_arp("10.0.0.1", "aa:bb:cc:dd:ee:01"))
    alert = m.feed(_arp("10.0.0.1", "aa:bb:cc:dd:ee:02"))
    assert alert is not None
    assert "10.0.0.1" in alert
    assert "aa:bb:cc:dd:ee:01" in alert
    assert "aa:bb:cc:dd:ee:02" in alert


def test_ignores_zero_addresses():
    m = arp_sieve.ArpMonitor()
    assert m.feed(_arp("0.0.0.0", "00:00:00:00:00:00")) is None
    assert m.summary() == {}


def test_benign_pcap_no_alerts():
    m = arp_sieve.ArpMonitor()
    alerts = arp_sieve.analyze_pcap(str(ROOT / "samples" / "benign.pcap"), m)
    assert alerts == []


def test_poisoned_pcap_alerts():
    m = arp_sieve.ArpMonitor()
    alerts = arp_sieve.analyze_pcap(str(ROOT / "samples" / "poisoned.pcap"), m)
    assert len(alerts) >= 1
    assert "ALERT" in alerts[0]
