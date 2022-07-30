import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

TCP_IP = '127.0.0.1'
TCP_PORT = 5005
BUFFER_SIZE = 1024
Name = "Sensor#6"
EID = "6"
EIP = "192.168.1.7"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect ((TCP_IP, TCP_PORT))

#Generate PK and PrK
private_key = private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()
pem = public_key.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
)
cipPem = base64.b64encode(pem)

#Receive SID
SID = s.recv(BUFFER_SIZE).decode()
print(SID)

#Registration Token
def regisToken(SID):
    bToken = str.encode("-".join([EID, EIP, SID]))
    sign = private_key.sign(
        bToken,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    ciphertext = base64.b64encode(sign)
    return ciphertext
token = regisToken(SID).decode()

#Send Data
s.sendall(str.encode("-".join([Name, EID, EIP, token, cipPem.decode()])))


data = s.recv(BUFFER_SIZE)
s.close()
print("Status : ", data.decode())
    