import scapy.all as scapy
import sys
from scapy.layers import http, dns
print("  ____            _        _        _                _                    ")
print(" |  _ \ __ _  ___| | _____| |_     / \   _ __   __ _| |_   _ _______ _ __ ")
print(" | |_) / _` |/ __| |/ / _ \ __|   / _ \ | '_ \ / _` | | | | |_  / _ \ '__|")
print(" |  __/ (_| | (__|   <  __/ |_   / ___ \| | | | (_| | | |_| |/ /  __/ |   ")
print(" |_|   \__,_|\___|_|\_\___|\__| /_/   \_\_| |_|\__,_|_|\__, /___\___|_|   ")
print("                                                       |___/              ")
print("                                                                          ")
print("       By s4f3s4f4r1                                                      ")
def packet_sniffer(packet):
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        # Display basic IP information
        print(f"Source IP: {source_ip}  Destination IP: {destination_ip}  Protocol: {protocol}")

        # Check for TCP packets
        if packet.haslayer(scapy.TCP):
            tcp_layer = packet[scapy.TCP]
            print(f"TCP Packet - Source Port: {tcp_layer.sport}  Destination Port: {tcp_layer.dport}")
            
            # Check if packet contains HTTP layer
            if packet.haslayer(http.HTTPRequest):
                http_layer = packet[http.HTTPRequest]
                print(f"HTTP Request - Host: {http_layer.Host.decode()}  Path: {http_layer.Path.decode()}")
            
        # Check for UDP packets
        elif packet.haslayer(scapy.UDP):
            udp_layer = packet[scapy.UDP]
            print(f"UDP Packet - Source Port: {udp_layer.sport}  Destination Port: {udp_layer.dport}")
            
            # Check for DNS layer
            if packet.haslayer(dns.DNSQR):
                dns_layer = packet[dns.DNSQR]
                print(f"DNS Query - Requested Host: {dns_layer.qname.decode()}")

        # Check for any raw data payload in the packet (useful for HTTP POST data, etc.)
        if packet.haslayer(scapy.Raw):
            raw_data = packet[scapy.Raw].load
            print(f"Raw Data: {raw_data.decode(errors='ignore')}")

        print("=" * 50)  # Separator for each packet

def main(interface):
    print(f"Starting packet sniffer on interface: {interface}")
    scapy.sniff(iface=interface, prn=packet_sniffer, store=False)

if __name__ == "__main__":
    interface = input("Enter the interface to sniff (e.g., wlan0, eth0): ")
    main(interface)
