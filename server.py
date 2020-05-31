import socket
import time
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
server.settimeout(1)
#Assigning pot to server
server.bind(("", 8000))
#Broadcasting a message
message = b"Lorem ipsum"
#Sending message after 4 seconds
while True:
    server.sendto(message, ('<broadcast>', 8001))
    print("Message Broadcasted!")
    time.sleep(4)
