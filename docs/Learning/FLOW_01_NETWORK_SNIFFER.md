# Flow 01 - Network Sniffer

## Objective
Capture live packets from host network.

## Primary File
- `Backend/network/sniffer.py`

## What It Does
- Uses Scapy `sniff()` to capture packets.
- Extracts source/destination IP and protocol info.
- Writes packet rows to `network_traffic.csv`.

## Current Role In Final Architecture
- Legacy/standalone capture path.
- Useful for raw packet logging and quick debugging.
- Not the main DB pipeline used by API + ML + DSL flow.

## Run (standalone)
```bash
python Backend/network/sniffer.py
```

## Output
- Appends rows in `network_traffic.csv`.
