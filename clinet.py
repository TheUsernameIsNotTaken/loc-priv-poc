# Basic python script to use IPv6 localhost socket communication. This is the client part of the app.

# Imports
import socket
import struct

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