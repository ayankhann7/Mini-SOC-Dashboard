from scapy.all import IP, TCP, wrpcap
import time

packets = []

# 1. Normal traffic
packets.append(IP(src="192.168.1.10", dst="10.0.0.1")/TCP(dport=80)/b"GET / HTTP/1.1\r\n")

# 2. Port scan from 10.0.0.20 (5 different ports)
for port in [21, 22, 23, 25, 80, 443]:
    packets.append(IP(src="10.0.0.20", dst="192.168.1.100")/TCP(dport=port))

# 3. Excessive requests from 10.0.0.30 (15+ packets)
for _ in range(20):
    packets.append(IP(src="10.0.0.30", dst="192.168.1.100")/TCP(dport=80)/b"GET / HTTP/1.1\r\n")

# 4. Directory Brute force (404 errors) from 192.168.1.6
for _ in range(12):
    packets.append(IP(src="192.168.1.6", dst="10.0.0.1")/TCP(dport=80)/b"HTTP/1.1 404 Not Found\r\n")

# 5. Brute force login (Failed) from 10.0.0.10
for _ in range(6):
    packets.append(IP(src="10.0.0.10", dst="10.0.0.1")/TCP(dport=22)/b"login:failed")

# Write to file
wrpcap("dataset/sample_capture.pcap", packets)
print("sample_capture.pcap generated in dataset/ directory.")
