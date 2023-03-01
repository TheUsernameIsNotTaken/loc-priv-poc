# Basic python script to use IPv6 localhost socket communication. This is the client part of the app.

# Imports
import socket

client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
client.connect(("fe80::b651:d81e:e8a3:df50%12", 9999))

client.send("Hello from spaceship!".encode())
print(client.recv(1024).decode())
