from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import csv
from datetime import datetime
import os 

# Open CSV file for writing
if not os.path.exists("network_traffic.csv"):
    with open("network_traffic.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Time", "Source IP", "Destination IP", "Protocol", "Size"])


def write_to_csv(data):    
    with open("network_traffic.csv", "a", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(data)



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

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        write_to_csv([timestamp, src_ip, dst_ip, protocol, size])

sniff(prn=process_packet, store=False,count=50)  # Capture 100 packets, adjust as needed