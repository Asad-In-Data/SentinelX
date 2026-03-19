from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import csv
from datetime import datetime

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "Other"

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"

        size = len(packet)

        print(f"Source: {src_ip} → Dest: {dst_ip} | Protocol: {protocol} | Size: {size}")

sniff(prn=process_packet, store=False)