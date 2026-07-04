# CodeAlpha Network Sniffer

## Overview
A lightweight Python network‑packet sniffer built for the CodeAlpha cybersecurity internship.

- Captures live packets using **Scapy**.
- Displays timestamp, protocol, source/destination IPs & ports, and payload size.
- Optional CSV export (`--csv`).
- Colour‑coded console output for quick visual parsing.

## Prerequisites
```powershell
pip install scapy colorama
```
Run the script with administrator / root privileges.

## Usage
```powershell
python network_sniffer.py [--filter <BPF_FILTER>] [--count N] [--csv]
```
- `--filter` – BPF filter string (e.g., `"tcp"`, `"udp"`, `"port 80"`).
- `--count` – Number of packets to capture (0 = unlimited until Ctrl+C).
- `--csv` – Save captured data to `packets.csv`.

## Examples
```powershell
# Capture all packets until stopped
python network_sniffer.py

# Capture only TCP packets, stop after 20 packets
python network_sniffer.py --filter "tcp" --count 20

# Capture everything and save to CSV
python network_sniffer.py --csv
```

## License
MIT – feel free to adapt for learning purposes.
