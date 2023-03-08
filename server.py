# Basic python script to use IPv6 localhost socket communication. This is the server side of the app.

# Imports
import socket

"""
# Define the source and destination addresses and port numbers
src_addr = "::2"
dst_addr = "::1"
src_port = 8888
dst_port = 9999

# Create a socket for the sniffer tool
sniffer = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)

# Bind the socket to the address
sniffer.bind((dst_addr, dst_port))

# Receive the packet
while True:
    print("Waiting for packet.")
    packet, addr = sniffer.recvfrom(65535)
    src_port_p, dst_port_p, seq, ack, offset_reserved_flags, window, checksum, urg_ptr = struct.unpack("!HHLLBBHHH", packet[20:40])
    if src_port == src_port_p and src_addr == addr:
        # Respond to the sender
        print("Correct.")
    else:
        print("Incorrect.")
    # Basic exit, without constant button check.
    choice = input("Enter Q to quit, or press return to continue")
    if choice.lower() == "q":
        sniffer.close()
        break
"""


# Create a datagram socket
server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

# Bind to address and ip
server.bind(("::1", 9999))
print("UDP server up and listening")

# Listen for incoming datagrams
while True:
    bytesAddressPair = server.recvfrom(1024)
    message = bytesAddressPair[0]
    address = bytesAddressPair[1]
    # Format
    clientMsg = "Message from Client:{}".format(message)
    clientIP = "Client IP Address:{}".format(address)
    # Show the message and IP
    print(clientMsg)
    print(clientIP)
    # Sending a reply to client
    server.sendto("Hello, this is Huston!".encode(), address)
    # Basic exit, without constant button check.
    choice = input("Enter Q to quit, or press return to continue")
    if choice.lower() == "q":
        server.close()
        break


"""
# Create server workflow
# Open socket, bind to port, then wait for connection.
server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
server.bind(("::1", 9999))     # Knows link-local address too!

server.listen()

while True:
    client, addr = server.accept()
    msg = client.recv(1024).decode()
    print(msg)
    client.send("Hello, this is Huston!".encode())
    # Basic exit, without constant button check.
    choice = input("Enter Q to quit, or press return to continue")
    if choice.lower() == "q":
        server.close()
        break
"""
