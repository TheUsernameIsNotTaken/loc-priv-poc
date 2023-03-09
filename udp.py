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

"""
import socket
import struct

VERSION_OFF = 0
IHL_OFF = VERSION_OFF
DSCP_OFF = IHL_OFF + 1
ECN_OFF = DSCP_OFF
LENGTH_OFF = DSCP_OFF + 1
ID_OFF = LENGTH_OFF + 2
FLAGS_OFF = ID_OFF + 2
OFF_OFF = FLAGS_OFF
TTL_OFF = OFF_OFF + 2
PROTOCOL_OFF = TTL_OFF + 1
IP_CHECKSUM_OFF = PROTOCOL_OFF + 1
SRC_IP_OFF = IP_CHECKSUM_OFF + 2
DEST_IP_OFF = SRC_IP_OFF + 4
SRC_PORT_OFF = DEST_IP_OFF + 4
DEST_PORT_OFF = SRC_PORT_OFF + 2
UDP_LEN_OFF = DEST_PORT_OFF + 2
UDP_CHECKSUM_OFF = UDP_LEN_OFF + 2
DATA_OFF = UDP_CHECKSUM_OFF + 2

IP_PACKET_OFF = VERSION_OFF
UDP_PACKET_OFF = SRC_PORT_OFF


def parse(data):
    packet = {}
    packet['version'] = data[VERSION_OFF] >> 4
    packet['IHL'] = data[IHL_OFF] & 0x0F
    packet['DSCP'] = data[DSCP_OFF] >> 2
    packet['ECN'] = data[ECN_OFF] & 0x03
    packet['length'] = (data[LENGTH_OFF] << 8) + data[LENGTH_OFF + 1]
    packet['Identification'] = (data[ID_OFF] << 8) + data[ID_OFF + 1]
    packet['Flags'] = data[FLAGS_OFF] >> 5
    packet['Offset'] = ((data[OFF_OFF] & 0b11111) << 8) + data[OFF_OFF + 1]
    packet['TTL'] = data[TTL_OFF]
    packet['Protocol'] = data[PROTOCOL_OFF]
    packet['Checksum'] = (data[IP_CHECKSUM_OFF] << 8) + data[IP_CHECKSUM_OFF + 1]
    packet['src_ip'] = '.'.join(map(str, [data[x] for x in range(SRC_IP_OFF, SRC_IP_OFF + 4)]))
    packet['dest_ip'] = '.'.join(map(str, [data[x] for x in range(DEST_IP_OFF, DEST_IP_OFF + 4)]))
    packet['src_port'] = (data[SRC_PORT_OFF] << 8) + data[SRC_PORT_OFF + 1]
    packet['dest_port'] = (data[DEST_PORT_OFF] << 8) + data[DEST_PORT_OFF + 1]
    packet['udp_length'] = (data[UDP_LEN_OFF] << 8) + data[UDP_LEN_OFF + 1]
    packet['UDP_checksum'] = (data[UDP_CHECKSUM_OFF] << 8) + data[UDP_CHECKSUM_OFF + 1]
    packet['data'] = ''.join(map(chr, [data[DATA_OFF + x] for x in range(0, packet['udp_length'] - 8)]))

    return packet


def udp_send(data, dest_addr, src_addr=('122.1.1.1', 9999)):
    # Generate pseudo header
    src_ip, dest_ip = ip2int(src_addr[0]), ip2int(dest_addr[0])
    src_ip = struct.pack('!4B', *src_ip)
    dest_ip = struct.pack('!4B', *dest_ip)

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
    pseudo_header = struct.pack('!BBH', zero, protocol, udp_length)
    pseudo_header = src_ip + dest_ip + pseudo_header
    udp_header = struct.pack('!4H', src_port, dest_port, udp_length, checksum)
    checksum = checksum_func(pseudo_header + udp_header + data)
    udp_header = struct.pack('!4H', src_port, dest_port, udp_length, checksum)
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as s:
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


def ip2int(ip_addr):
    if ip_addr == 'localhost':
        ip_addr = '127.0.0.1'
    return [int(x) for x in ip_addr.split('.')]


def udp_recv(addr, size):
    zero = 0
    protocol = 17
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as s:
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
    udp_send("hello", ('122.1.1.2', 9999))
    print("send")
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


def udp_send(data, dest_addr, src_addr):
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

    ver = 6 << 4
    traffic = 0
    flow = 0
    hl = 64
    ip_header = struct.pack('!BBHHBB', ver, traffic, flow, udp_length, protocol, hl)
    ip_header += src_ip + dest_ip
    print("IP header: ", ip_header)

    checksum = 0
    pseudo_header = struct.pack('!IBBBH', udp_length, zero, zero, zero, protocol)
    pseudo_header = src_ip + dest_ip + pseudo_header
    print("Pseudo header: ", pseudo_header)
    udp_header = struct.pack('!4H', src_port, dest_port, udp_length, checksum)
    checksum = calc_checksum(pseudo_header + udp_header + data)
    udp_header = struct.pack('!4H', src_port, dest_port, udp_length, checksum)

    #, socket.IPPROTO_UDP
    with socket.socket(socket.AF_INET6, socket.SOCK_RAW) as s:
        print("UDP header: ", udp_header)
        print("Data: ", data)
        print("Address: ", dest_addr)
        packet = ip_header + udp_header + data
        print("Packet: ", packet)
        s.sendto(packet, dest_addr)


def calc_checksum(packet):
    total = 0

    # Add up 16-bit words
    num_words = len(packet) // 2
    for chunk in struct.unpack("!%sH" % num_words, packet[0:num_words*2]):
        total += chunk

    # Add any left over byte
    if len(packet) % 2:
        total += ord(packet[-1]) << 8

    # Fold 32-bits into 16-bits
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return (~total + 0x10000 & 0xffff)

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
    dest_a = ('1111::2', 9999, 0, 0)
    self_a = ('1111::1', 9999, 0, 0)
    udp_send("Hello, this is spaceship!", dest_a, self_a)
