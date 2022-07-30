# fog
import socket
from _thread import *
import hashlib
import mysql.connector
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend as crypto_default_backend
import base64
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import poly1305

TCP_IP = '127.0.0.1'
TCP_PORT = 5005
BUFFER_SIZE = 1024
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #TCP
s.bind((TCP_IP, TCP_PORT))
s.listen(1)

#SID
mac = "E0D4E85AA4E1"
encode = hashlib.sha1(mac.encode())
sha = encode.hexdigest()
SID = "WeatherStation"+sha[-5:]

while True:
    conn , addr = s.accept()

    #Database
    mydb = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="kp"
    )
    cursor = mydb.cursor(buffered=True)

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

    #Save Data to Database
    def Save(Name, SID, EID, EIP, regisToken) :
        cursor.execute("insert into devices(Name, SID, EID, EIP, regisToken) values ('"+Name+"', '"+SID+"', '"+EID+"', '"+EIP+"', '"+regisToken+"')")
        mydb.commit()
        msg = "Device Berhasil Ditambah"
        conn.send(msg.encode())
        print("Device berhasil ditambahkan ke database")

    #Send SID
    conn.send(SID.encode())

    #Save T3 & T4
    def SaveT(t3, t4) :
        #Check t1 and t2
        st3 = t3.decode('utf-8')
        st4 = t4.decode('utf-8')
        cursor.execute("insert into block(t3, t4) values ('"+st3+"', '"+st4+"')")
        mydb.commit()
        print("Transaksi berhasil dimasukkan ke database")

    def transaction3(token, SID):
        bSID = SID.encode()
        key = b"fTjWnZr4u7x!A%D*G-KaNdRgUkXp2s5v"
        sign = private_key.sign(
            bSID,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        temp = b''.join([token.encode(),b',', sign])
        p = poly1305.Poly1305.generate_tag(key, temp)
        enc = public_key.encrypt(
            p,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        ciphertext = base64.b64encode(enc)
        return ciphertext

    def transaction4(SID, EID, EIP, EIDpk):
        all = "-".join([SID, EID, EIP])
        key = b"2r5u8x/A?D(G+KbPeShVmYp3s6v9y$B&"
        sign = private_key.sign(
            all.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        p = poly1305.Poly1305.generate_tag(key, sign)
        enc = EIDpk.encrypt(
            p,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        ciphertext = base64.b64encode(enc)
        return ciphertext

    #Variable
    tName, tEID, tEIP, token, tEIDpk = [str(i) for i in conn.recv(BUFFER_SIZE).decode().split('-')]
    EIDpk = load_pem_public_key(base64.b64decode(tEIDpk))

    #Check Name, EID, EIP From Device
    print(tName)
    cursor.execute("SELECT Count(SID) FROM devices where SID = '"+SID+"'")
    cSID = cursor.fetchone()
    cursor.execute("SELECT Count(EID) FROM devices where EID = '"+tEID+"'")
    cEID = cursor.fetchone()
    print(tName)
    cursor.execute("SELECT Count(EIP) FROM devices where EIP = '"+tEIP+"'")
    cEIP = cursor.fetchone()
    print(cEIP[0])
    if (1 <= cSID[0]) :
        print("SID ditemukan")
    if (1 != cEID[0]) :
        print("EID tidak ditemukan")
        if (1 != cEIP[0]) :
            Save(tName, SID, tEID, tEIP, token)
    else :
        msg = "Device sudah ada di database"
        conn.send(msg.encode())
        print("Tambah device gagal")

    #Run All
    t3 = transaction3(token, SID)
    t4 = transaction4(SID, tEID, tEIP, EIDpk)
    SaveT(t3, t4)
    
conn.close ()