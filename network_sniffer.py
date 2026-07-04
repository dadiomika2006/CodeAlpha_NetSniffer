# network_sniffer.py
"""Network Sniffer for CodeAlpha Internship

This script captures live network packets using Scapy, prints a concise summary
for each packet, and optionally saves the data to a CSV file.

Requirements:
    pip install scapy colorama

Usage:
    python network_sniffer.py [--filter <bpf_filter>] [--count N] [--csv]

Examples:
    python network_sniffer.py --filter "tcp"      # only TCP packets
    python network_sniffer.py --count 10          # capture 10 packets then exit
    python network_sniffer.py --csv               # save output to packets.csv
"""

import argparse
import datetime
import sys
from collections import Counter
from typing import Optional

# Scapy import (fails gracefully if not installed)
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
except ImportError:
    sys.stderr.write("Scapy not installed. Run 'pip install scapy' first.\n")
    sys.exit(1)

# Optional colour support
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False
    class _Dummy:
        def __getattr__(self, name):
            return ""
    Fore = Style = _Dummy()

def colour(text: str, code: str) -> str:
    return f"{code}{text}{Style.RESET_ALL}" if COLOR_ENABLED else text

def format_packet(pkt) -> Optional[str]:
    if IP not in pkt:
        return None
    ip = pkt[IP]
    src, dst = ip.src, ip.dst
    proto = {6: "TCP", 17: "UDP"}.get(ip.proto, str(ip.proto))
    src_port = dst_port = "-"
    if TCP in pkt:
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    payload = len(pkt[Raw].load) if Raw in pkt else 0
    ts = datetime.datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S")
    proto_col = colour(proto, Fore.GREEN if proto == "TCP" else Fore.CYAN if proto == "UDP" else Fore.MAGENTA)
    return f"[{ts}] {proto_col} {src}:{src_port} → {dst}:{dst_port}  payload:{payload}B"

def packet_handler(pkt):
    line = format_packet(pkt)
    if line:
        print(line)
        if csv_writer:
            csv_writer.writerow([datetime.datetime.fromtimestamp(pkt.time), proto, src, src_port, dst, dst_port, payload])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live network packet sniffer (Scapy)")
    parser.add_argument("--filter", type=str, default="", help="BPF filter, e.g., 'tcp' or 'udp'")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--csv", action="store_true", help="Save captured data to packets.csv")
    args = parser.parse_args()

    csv_writer = None
    if args.csv:
        import csv
        csv_file = open("packets.csv", "w", newline="", encoding="utf-8")
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["timestamp", "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "payload_bytes"])

    try:
        print(colour("[+] Starting capture – press Ctrl+C to stop", Fore.YELLOW))
        sniff(prn=packet_handler, filter=args.filter, count=args.count, store=False)
    except KeyboardInterrupt:
        print(colour("\n[!] Capture stopped by user", Fore.RED))
    finally:
        if args.csv:
            csv_file.close()
            print(colour("[+] CSV saved as packets.csv", Fore.YELLOW))
        sys.exit(0)
