from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import csv
from datetime import datetime
import os 

global tcp_count, udp_count, icmp_count, other_count
tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0
src_port = None
dst_port = None


# Open CSV file for writing
if not os.path.exists("network_traffic.csv"):
    with open("network_traffic.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Time", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Size"])


def write_to_csv(data):    
    with open("network_traffic.csv", "a", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(data)



def process_packet(packet):
    global tcp_count, udp_count, icmp_count, other_count
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "Other"

        if packet.haslayer(TCP):
            protocol = "TCP"
            tcp_count += 1
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            udp_count += 1
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            icmp_count += 1
            src_port = None
            dst_port = None
        else:  
            protocol = "Other"         
            other_count += 1


        size = len(packet)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        write_to_csv([timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size])
        
        total = tcp_count + udp_count + icmp_count + other_count

        if total % 10 == 0:
            print("\n--- Protocol Stats ---")
            print(f"TCP: {tcp_count}")
            print(f"UDP: {udp_count}")
            print(f"ICMP: {icmp_count}")
            print(f"Other: {other_count}")

sniff(prn=process_packet, store=False,count=50)  # Capture 100 packets, adjust as needed