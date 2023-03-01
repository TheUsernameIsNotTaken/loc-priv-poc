# Basic python script to use IPv6 localhost socket communication. This is the server side of the app.

# Imports
import socket

# Create server workflow
# Open socket, bind to port, then wait for connection.
server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
server.bind(("fe80::b651:d81e:e8a3:df50%12", 9999))     # Knows link-local address too!

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

