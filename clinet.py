# Basic python script to use IPv6 localhost socket communication. This is the client part of the app.

# Imports
import socket
import struct

# Create a raw socket
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)

# Define the source and destination addresses and port numbers
src_addr = "::2"
dst_addr = "::1"
src_port = 8888
dst_port = 9999

def checksum_func(data):
    checksum = 0
    data_len = len(data)
    if (data_len % 2):
        data_len += 1
        data += struct.pack('!B', 0)

    for i in range(0, data_len, 2):
        w = (data[i] << 8) + (data[i + 1])
        checksum += w

    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum

pseudo_header = struct.pack("!16s16sHH", socket.inet_pton(socket.AF_INET6, src_addr),
                            socket.inet_pton(socket.AF_INET6, dst_addr), 6, len(tcp_header))
pseudo_packet = pseudo_header + tcp_header
for i in range(0, len(pseudo_packet), 2):
    tcp_checksum += int.from_bytes(pseudo_packet[i:i+2], byteorder='big')
tcp_checksum = checksum_func(pseudo_packet + data)
tcp_header = struct.pack("!HHLLBBHHH", src_port, dst_port, 0, 0, 5, tcp_checksum, 0, 0, 0)
packet = tcp_header

# Set the IP header fields
saddr = socket.inet_pton(socket.AF_INET6, src_addr)
daddr = socket.inet_pton(socket.AF_INET6, dst_addr)
protocol = socket.IPPROTO_TCP
header = struct.pack('!16s16sBBH', saddr, daddr, 0, protocol, len(packet))

# Send the packet
s.sendto(header + packet, (dst_addr, dst_port))

"""
# Server and Client socket data.
serverAddressPort = ("::1", 9999)
client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
client.bind(("::abcd", 9990))

# Return Address
print(client.getsockname())

# Send to server using created UDP socket
client.sendto("Hello from spaceship!".encode(), serverAddressPort)

# Receive return message
msgFromServer = client.recvfrom(1024)
msg = "Message from Server {}".format(msgFromServer[0])
print(msg)
"""

"""
# Create a raw socket
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)

#Set payload message
payload = b'Hello, Huston!'

# Set the IPv6 header fields
source_ip = '::1'
dest_ip = '::1'
ip_version = 6
traffic_class = 0
flow_label = 0
payload_len = len(payload)
next_header = socket.IPPROTO_TCP
hop_limit = 64

# Pack the IPv6 header fields into a binary string
ipv6_header = struct.pack('!BBHI', (ip_version << 4) | (traffic_class >> 4),
                          (traffic_class & 0x0f) << 4 | (flow_label >> 16),
                          flow_label & 0xffff, payload_len)
ipv6_header += struct.pack('!B', next_header)
ipv6_header += struct.pack('!B', hop_limit)
ipv6_header += socket.inet_pton(socket.AF_INET6, source_ip)
ipv6_header += socket.inet_pton(socket.AF_INET6, dest_ip)

# Send the packet with the modified source address
s.sendto(ipv6_header + payload, socket.inet_pton(socket.AF_INET6, dest_ip))
"""

"""
client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
client.connect(("localhost", 9999))

# Return Address
print(client.getsockname())

client.send("Hello from spaceship!".encode())
print(client.recv(1024).decode())
"""