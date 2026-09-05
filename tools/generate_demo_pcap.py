"""Generate the deterministic synthetic capture used by the one-click demo."""

from __future__ import annotations

import argparse
from pathlib import Path

from scapy.all import Ether, ICMP, IP, Raw, TCP, UDP, wrpcap


def build_packets() -> list[object]:
    base = {"src": "10.20.0.10", "dst": "10.20.0.20"}
    packets = [
        Ether() / IP(**base) / TCP(sport=49152, dport=443, flags="S", seq=100),
        Ether() / IP(**base) / TCP(sport=49152, dport=443, flags="A", seq=101) / Raw(load=b"GET /demo HTTP/1.1\r\nHost: sample.local\r\n\r\n"),
        Ether() / IP(**base) / UDP(sport=53000, dport=53) / Raw(load=b"synthetic dns question"),
        Ether() / IP(**base) / TCP(sport=49152, dport=443, flags="F", seq=102),
        Ether() / IP(src=base["dst"], dst=base["src"]) / TCP(sport=8443, dport=49200, flags="S", seq=400),
        Ether() / IP(src=base["dst"], dst=base["src"]) / TCP(sport=8443, dport=49200, flags="A", seq=401) / Raw(load=b"artifact=synthetic\nstatus=review"),
        Ether() / IP(**base) / UDP(sport=54000, dport=123) / Raw(load=b"synthetic ntp sample"),
        Ether() / IP(**base) / ICMP(),
        Ether() / IP(src=base["dst"], dst=base["src"]) / TCP(sport=8443, dport=49200, flags="F", seq=402),
    ]
    for index, packet in enumerate(packets):
        packet.time = 1_700_000_000 + index
    return packets


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("public/samples/suspicious-demo.pcap"))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(args.output), build_packets())
    print(f"Wrote {len(build_packets())} deterministic synthetic packets to {args.output}")


if __name__ == "__main__":
    main()
