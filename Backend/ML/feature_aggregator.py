"""
Feature Aggregator for Live Network Traffic IDS
Implements proper KDD Cup feature extraction with sliding window aggregation
"""

import pandas as pd
import numpy as np
from collections import defaultdict, deque
from datetime import datetime, timedelta
from scapy.all import IP, TCP, UDP, ICMP


class NetworkFeatureAggregator:
    """
    Extracts KDD Cup features from live network traffic
    using sliding window aggregation for statistical features
    """
    
    def __init__(self, 
                 window_size=10,  # seconds
                 feature_names=None):
        """
        Args:
            window_size: Time window for aggregation (seconds)
            feature_names: List of 41 KDD Cup feature names
        """
        self.window_size = window_size
        self.feature_names = feature_names or []
        
        # Buffers for window aggregation
        self.packet_window = deque(maxlen=1000)  # Store recent packets
        self.connection_dict = defaultdict(list)  # (src_ip, dst_ip) -> packets
        self.service_dict = defaultdict(list)     # service -> packets
        
        # Timestamp tracking
        self.last_cleanup = datetime.now()
        self.cleanup_interval = 5  # seconds
        
    def add_packet(self, packet):
        """Add packet to window and maintain buffers"""
        try:
            pkt_info = {
                'timestamp': datetime.now(),
                'packet': packet,
                'ip_layer': packet[IP] if packet.haslayer(IP) else None,
                'tcp_layer': packet[TCP] if packet.haslayer(TCP) else None,
                'udp_layer': packet[UDP] if packet.haslayer(UDP) else None,
                'icmp_layer': packet[ICMP] if packet.haslayer(ICMP) else None,
            }
            
            self.packet_window.append(pkt_info)
            
            # Index by connection and service
            if pkt_info['ip_layer']:
                src_ip = pkt_info['ip_layer'].src
                dst_ip = pkt_info['ip_layer'].dst
                conn_key = (src_ip, dst_ip)
                self.connection_dict[conn_key].append(pkt_info)
                
                # Extract service
                service = self._get_service(pkt_info)
                self.service_dict[service].append(pkt_info)
            
            # Cleanup old entries periodically
            if (datetime.now() - self.last_cleanup).total_seconds() > self.cleanup_interval:
                self._cleanup_old_packets()
                
        except Exception as e:
            print(f"⚠️ Error adding packet: {e}")
    
    def _cleanup_old_packets(self):
        """Remove packets older than window_size from buffers"""
        cutoff_time = datetime.now() - timedelta(seconds=self.window_size)
        
        # Clean connection dict
        for conn_key in list(self.connection_dict.keys()):
            self.connection_dict[conn_key] = [
                p for p in self.connection_dict[conn_key] 
                if p['timestamp'] > cutoff_time
            ]
            if not self.connection_dict[conn_key]:
                del self.connection_dict[conn_key]
        
        # Clean service dict
        for service in list(self.service_dict.keys()):
            self.service_dict[service] = [
                p for p in self.service_dict[service] 
                if p['timestamp'] > cutoff_time
            ]
            if not self.service_dict[service]:
                del self.service_dict[service]
        
        self.last_cleanup = datetime.now()
    
    def _get_service(self, pkt_info):
        """Determine service from packet"""
        if pkt_info['tcp_layer']:
            dport = pkt_info['tcp_layer'].dport
            return self._port_to_service(dport)
        elif pkt_info['udp_layer']:
            dport = pkt_info['udp_layer'].dport
            return self._port_to_service(dport)
        return 'other'
    
    @staticmethod
    def _port_to_service(port):
        """Map port to service"""
        service_map = {
            20: 'ftp-data', 21: 'ftp', 23: 'telnet',
            25: 'smtp', 53: 'domain', 80: 'http',
            110: 'pop_3', 143: 'imap4', 443: 'https',
            465: 'smtp_ssl', 587: 'smtp', 993: 'imap_ssl',
            995: 'pop_3_ssl', 3306: 'mysql', 5432: 'postgres',
            6379: 'redis', 27017: 'mongodb'
        }
        return service_map.get(port, 'other')
    
    def _get_protocol(self, pkt_info):
        """Extract protocol type"""
        if pkt_info['tcp_layer']:
            return 'tcp'
        elif pkt_info['udp_layer']:
            return 'udp'
        elif pkt_info['icmp_layer']:
            return 'icmp'
        return 'other'
    
    def _get_flag(self, pkt_info):
        """Extract TCP flags"""
        if pkt_info['tcp_layer']:
            flags = pkt_info['tcp_layer'].flags
            if flags == 'S':
                return 'S0'   # SYN
            elif flags == 'R':
                return 'REJ'  # RST
            elif flags == 'SA':
                return 'SF'   # SYN-ACK
            elif flags == 'F':
                return 'FIN'  # FIN
            elif flags == 'A':
                return 'RSTR' # ACK only
            else:
                return 'SF'   # default
        return 'SF'
    
    def extract_features(self, current_packet):
        """
        Extract all 41 KDD Cup features from current packet
        and window statistics
        """
        self.add_packet(current_packet)
        
        if not current_packet.haslayer(IP):
            return None
        
        features = {}
        
        # Basic packet features
        ip_layer = current_packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        conn_key = (src_ip, dst_ip)
        service = self._get_service({'tcp_layer': current_packet[TCP] if current_packet.haslayer(TCP) else None,
                                     'udp_layer': current_packet[UDP] if current_packet.haslayer(UDP) else None})
        
        # === BASIC FEATURES ===
        features['duration'] = 0  # Single packet has 0 duration
        features['protocol_type'] = self._get_protocol({'tcp_layer': current_packet[TCP] if current_packet.haslayer(TCP) else None,
                                                        'udp_layer': current_packet[UDP] if current_packet.haslayer(UDP) else None,
                                                        'icmp_layer': current_packet[ICMP] if current_packet.haslayer(ICMP) else None})
        features['service'] = service
        features['flag'] = self._get_flag({'tcp_layer': current_packet[TCP] if current_packet.haslayer(TCP) else None})
        
        # === PACKET SIZE FEATURES ===
        features['src_bytes'] = len(current_packet)
        features['dst_bytes'] = 0  # Single packet perspective - incoming from src
        
        # === LAND ATTACK FEATURE ===
        features['land'] = 1 if src_ip == dst_ip else 0
        
        # === FRAGMENTATION FEATURES ===
        features['wrong_fragment'] = 0  # Would need packet inspection
        features['urgent'] = 0
        
        # === CONNECTION ATTEMPT FEATURES ===
        features['hot'] = 0
        features['num_failed_logins'] = 0
        features['logged_in'] = 0
        features['num_compromised'] = 0
        features['root_shell'] = 0
        features['su_attempted'] = 0
        features['num_root'] = 0
        features['num_file_creations'] = 0
        features['num_shells'] = 0
        features['num_access_files'] = 0
        features['num_outbound_cmds'] = 0
        features['is_host_login'] = 0
        features['is_guest_login'] = 0
        
        # === WINDOW AGGREGATION FEATURES (CRITICAL!) ===
        
        # Count: connections from same src in window
        features['count'] = len(self.connection_dict[conn_key]) if conn_key in self.connection_dict else 1
        
        # Srv_count: connections to same dst_service in window
        features['srv_count'] = len(self.service_dict[service]) if service in self.service_dict else 1
        
        # Error rate features
        window_packets = list(self.packet_window)
        if window_packets:
            # Serror_rate: % SYN errors
            syn_errors = sum(1 for p in window_packets 
                            if p.get('tcp_layer') and p['tcp_layer'].flags == 'R')
            features['serror_rate'] = syn_errors / len(window_packets) if window_packets else 0
            
            # Srv_serror_rate: same service SYN errors
            service_packets = self.service_dict.get(service, [])
            if service_packets:
                srv_syn_errors = sum(1 for p in service_packets 
                                    if p.get('tcp_layer') and p['tcp_layer'].flags == 'R')
                features['srv_serror_rate'] = srv_syn_errors / len(service_packets)
            else:
                features['srv_serror_rate'] = 0
            
            # Rerror_rate: % RST errors (for this connection)
            rst_errors = sum(1 for p in self.connection_dict.get(conn_key, []) 
                           if p.get('tcp_layer') and p['tcp_layer'].flags == 'R')
            features['rerror_rate'] = rst_errors / features['count'] if features['count'] > 0 else 0
            
            # Srv_rerror_rate: RST errors for service
            srv_rst_errors = sum(1 for p in service_packets 
                               if p.get('tcp_layer') and p['tcp_layer'].flags == 'R')
            features['srv_rerror_rate'] = srv_rst_errors / len(service_packets) if service_packets else 0
        else:
            features['serror_rate'] = 0
            features['srv_serror_rate'] = 0
            features['rerror_rate'] = 0
            features['srv_rerror_rate'] = 0
        
        # Same_srv_rate: % connections to same service
        total_conns = len(window_packets) if window_packets else 1
        service_conns = len(self.service_dict.get(service, []))
        features['same_srv_rate'] = service_conns / total_conns if total_conns > 0 else 0
        
        # Diff_srv_rate: different services in window
        unique_services = len(self.service_dict)
        features['diff_srv_rate'] = unique_services / total_conns if total_conns > 0 else 0
        
        # Srv_diff_host_rate: different hosts for same service
        service_hosts = set()
        for pkt in self.service_dict.get(service, []):
            if pkt['ip_layer']:
                service_hosts.add(pkt['ip_layer'].src)
        features['srv_diff_host_rate'] = len(service_hosts) / features['srv_count'] if features['srv_count'] > 0 else 0
        
        # === DST HOST FEATURES ===
        dst_connections = [p for p in window_packets 
                          if p.get('ip_layer') and p['ip_layer'].dst == dst_ip]
        
        features['dst_host_count'] = len(dst_connections) if dst_connections else 1
        
        dst_service_conns = len([p for p in dst_connections 
                               if self._get_service(p) == service])
        features['dst_host_srv_count'] = dst_service_conns if dst_service_conns > 0 else 1
        
        features['dst_host_same_srv_rate'] = dst_service_conns / len(dst_connections) if dst_connections else 0
        
        # Different services to same dst
        dst_services = set()
        for p in dst_connections:
            dst_services.add(self._get_service(p))
        features['dst_host_diff_srv_rate'] = len(dst_services) / len(dst_connections) if dst_connections else 0
        
        # Same src port rate to dst
        same_port_conns = [p for p in dst_connections 
                          if p.get('tcp_layer') and p['tcp_layer'].sport == (current_packet[TCP].sport if current_packet.haslayer(TCP) else None)]
        features['dst_host_same_src_port_rate'] = len(same_port_conns) / len(dst_connections) if dst_connections else 0
        
        # SYN errors to dst
        dst_syn_errors = sum(1 for p in dst_connections 
                           if p.get('tcp_layer') and p['tcp_layer'].flags == 'S')
        features['dst_host_serror_rate'] = dst_syn_errors / len(dst_connections) if dst_connections else 0
        
        # SYN errors to same service on dst
        dst_srv_syn_errors = sum(1 for p in [x for x in dst_connections if self._get_service(x) == service] 
                                if p.get('tcp_layer') and p['tcp_layer'].flags == 'S')
        features['dst_host_srv_serror_rate'] = dst_srv_syn_errors / dst_service_conns if dst_service_conns > 0 else 0
        
        # RST errors to dst
        dst_rst_errors = sum(1 for p in dst_connections 
                           if p.get('tcp_layer') and p['tcp_layer'].flags == 'R')
        features['dst_host_rerror_rate'] = dst_rst_errors / len(dst_connections) if dst_connections else 0
        
        # RST errors to same service on dst
        dst_srv_rst_errors = sum(1 for p in [x for x in dst_connections if self._get_service(x) == service] 
                                if p.get('tcp_layer') and p['tcp_layer'].flags == 'R')
        features['dst_host_srv_rerror_rate'] = dst_srv_rst_errors / dst_service_conns if dst_service_conns > 0 else 0
        
        # Different hosts for same dst service
        dst_service_hosts = set()
        for p in [x for x in dst_connections if self._get_service(x) == service]:
            if p['ip_layer']:
                dst_service_hosts.add(p['ip_layer'].src)
        features['dst_host_srv_diff_host_rate'] = len(dst_service_hosts) / dst_service_conns if dst_service_conns > 0 else 0
        
        return pd.DataFrame([features])


if __name__ == "__main__":
    print("Feature Aggregator Module Loaded Successfully")
    print("Use: aggregator = NetworkFeatureAggregator(window_size=10)")
    print("     features_df = aggregator.extract_features(packet)")
