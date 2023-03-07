# Basic python script to use IPv6 localhost socket communication. This is the server side of the app.

# Imports
import socket

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
