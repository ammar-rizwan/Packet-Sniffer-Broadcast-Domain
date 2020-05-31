import socket

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
client.bind(("", 8002))
while True:
	message, addr = client.recvfrom(1024)
	print("message from server = %s"%message)
