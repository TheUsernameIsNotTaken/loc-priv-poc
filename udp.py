# Created by houluy (https://github.com/houluy)

"""
UDP Field:
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|      Source     |    Destination  |
|       Port      |       Port      |
+--------+--------+--------+--------+
|      Length     |     Checksum    |
+--------+--------+--------+--------+
|
|        data octets ...
+--------------- ...

UDP Pseudo Header
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|                                   |
|                                   |
|         v6 source address         |
|                                   |
+--------+--------+--------+--------+
|                                   |
|                                   |
|      v6 destination address       |
|                                   |
+--------+--------+--------+--------+
|            UDP length             |
+--------+--------+--------+--------+
|        Zeroes            |Protocol|
+--------+--------+--------+--------+

IP Header
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|Ver.|Traf.cl.|     Flow label      |
+--------+--------+--------+--------+
|  Payload length | Next h.|Hop lim.|
+--------+--------+--------+--------+
|                                   |
|                                   |
|         Source IP address         |
|                                   |
+--------+--------+--------+--------+
|                                   |
|                                   |
|       Destination IP address      |
|                                   |
+--------+--------+--------+--------+
"""

import socket
import struct

VERSION_OFF = 0                     # 0
TRAFFIC_OFF = VERSION_OFF           # 0
FLOW_OFF = TRAFFIC_OFF + 1          # 1
LENGTH_OFF = FLOW_OFF + 3           # 4
NEXT_HEADER_OFF = LENGTH_OFF + 2    # 6
HOP_LIM_OFF = NEXT_HEADER_OFF + 1   # 7
SRC_IP_OFF = HOP_LIM_OFF + 1        # 8
DEST_IP_OFF = SRC_IP_OFF + 16       # 24
SRC_PORT_OFF = DEST_IP_OFF + 16     # 40
DEST_PORT_OFF = SRC_PORT_OFF + 2    # 42
UDP_LEN_OFF = DEST_PORT_OFF + 2     # 44
UDP_CHECKSUM_OFF = UDP_LEN_OFF + 2  # 46
DATA_OFF = UDP_CHECKSUM_OFF + 2     # 48

IP_PACKET_OFF = VERSION_OFF
UDP_PACKET_OFF = SRC_PORT_OFF

# Parse header parts with offset
def parse(data):
    packet = {}
    packet['version'] = data[VERSION_OFF] >> 4
    packet['Traffic class'] = ((data[TRAFFIC_OFF] & 0x0F) << 8) + (data[TRAFFIC_OFF + 1] >> 4)
    packet['Flow label'] = ((data[FLOW_OFF] & 0x0F) << 16) + (data[TRAFFIC_OFF + 1] << 8) + data[TRAFFIC_OFF + 2]
    packet['Payload length'] = (data[LENGTH_OFF] << 8) + data[LENGTH_OFF + 1]
    packet['Next header'] = data[NEXT_HEADER_OFF]
    packet['Hop limit'] = data[HOP_LIM_OFF]
    packet['src_ip'] = '.'.join(map(str, [data[x] for x in range(SRC_IP_OFF, SRC_IP_OFF + 16)]))
    packet['dest_ip'] = '.'.join(map(str, [data[x] for x in range(DEST_IP_OFF, DEST_IP_OFF + 16)]))
    packet['src_port'] = (data[SRC_PORT_OFF] << 8) + data[SRC_PORT_OFF + 1]
    packet['dest_port'] = (data[DEST_PORT_OFF] << 8) + data[DEST_PORT_OFF + 1]
    packet['udp_length'] = (data[UDP_LEN_OFF] << 8) + data[UDP_LEN_OFF + 1]
    packet['UDP_checksum'] = (data[UDP_CHECKSUM_OFF] << 8) + data[UDP_CHECKSUM_OFF + 1]
    packet['data'] = ''.join(map(chr, [data[DATA_OFF + x] for x in range(0, packet['udp_length'] - 8)]))

    return packet


def udp_send(data, dest_addr, src_addr=('::1', 9999)):
    # Generate pseudo header
    src_ip = socket.inet_pton(socket.AF_INET6, src_addr[0])
    dest_ip = socket.inet_pton(socket.AF_INET6, dest_addr[0])

    zero = 0

    protocol = socket.IPPROTO_UDP

    # Check the type of data
    try:
        data = data.encode()
    except AttributeError:
        pass

    src_port = src_addr[1]
    dest_port = dest_addr[1]

    data_len = len(data)

    udp_length = 8 + data_len

    checksum = 0
    pseudo_header = struct.pack('!IBBBH', udp_length, zero, zero, zero, protocol, )
    pseudo_header = src_ip + dest_ip + pseudo_header
    udp_header = struct.pack('!4H', src_port, dest_port, udp_length, checksum)
    checksum = checksum_func(pseudo_header + udp_header + data)
    udp_header = struct.pack('!4H', src_port, dest_port, udp_length, checksum)
    with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_UDP) as s:
        print(udp_header)
        print(data)
        print((dest_ip, dest_port))
        s.sendto(udp_header + data, dest_addr)


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

def udp_recv(addr, size):
    zero = 0
    protocol = 17
    with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_UDP) as s:
        s.bind(addr)
        while True:
            data, src_addr = s.recvfrom(size)
            packet = parse(data)
            ip_addr = struct.pack('!8B', *[data[x] for x in range(SRC_IP_OFF, SRC_IP_OFF + 8)])
            udp_psuedo = struct.pack('!BB5H', zero, protocol, packet['udp_length'], packet['src_port'],
                                     packet['dest_port'], packet['udp_length'], 0)

            verify = verify_checksum(ip_addr + udp_psuedo + packet['data'].encode(), packet['UDP_checksum'])
            if verify == 0xFFFF:
                print(packet['data'])
            else:
                print('Checksum Error!Packet is discarded')


def verify_checksum(data, checksum):
    data_len = len(data)
    if (data_len % 2) == 1:
        data_len += 1
        data += struct.pack('!B', 0)

    for i in range(0, data_len, 2):
        w = (data[i] << 8) + (data[i + 1])
        checksum += w
        checksum = (checksum >> 16) + (checksum & 0xFFFF)

    return checksum


if __name__ == '__main__':
    server_a = ('::1', 8888)
    udp_send("Hello, this is spaceship!", server_a)
