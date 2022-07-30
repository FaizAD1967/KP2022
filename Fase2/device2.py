import socket

TCP_IP = '127.0.0.1'
TCP_PORT = 5005
BUFFER_SIZE = 1024
Name = "Sensor#5"
EID = "5"
EIP = "192.168.1.6"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect ((TCP_IP, TCP_PORT))

#Send Data
s.sendall(str.encode("-".join([Name, EID, EIP])))


data = s.recv(BUFFER_SIZE)
s.close()
print("Status : ", data.decode())
    