# fog
import socket
from _thread import *
import hashlib
import mysql.connector
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import poly1305
import base64

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

#Generate PK and PrK
private_key = private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

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

    #Save T1&T2
    def SaveT(t1, t2) :
        #Check t1 and t2
        st1 = t1.decode('utf-8')
        st2 = t2.decode('utf-8')
        cursor.execute("SELECT Count(t1) FROM block where t1 = '"+st1+"'")
        ct1 = cursor.fetchone()
        cursor.execute("SELECT Count(t2) FROM block where t2 = '"+st2+"'")
        ct2 = cursor.fetchone()
        if(ct1[0]==0 and ct2[0]==0):
            cursor.execute("insert into block(t1, t2) values ('"+st1+"', '"+st2+"')")
            mydb.commit()
            msg = "Transaksi Berhasil"
            conn.send(msg.encode())
            print("Transaksi berhasil dimasukkan ke database")
        else :
            print("Transaksi sudah pernah dilakukan")

    

    #Variable
    enc = conn.recv(BUFFER_SIZE)
    adminPubKey = load_pem_public_key(enc)

    #Check SID
    def checkSID(SID):
        cursor.execute("SELECT Count(SID) FROM header where SID = '"+SID+"'")
        cSID = cursor.fetchone()
        if (1 <= cSID[0]) :
            print("SID ditemukan \n")
        else :
            cursor.execute("insert into header(sid) values ('"+SID+"')")
            mydb.commit()
            print("SID berhasil ditambahkan \n")
    
    #Create T1 and T2 then Save it
    def transaction1(SID):
        bSID = SID.encode()
        enc = public_key.encrypt(
            bSID,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        ciphertext = base64.b64encode(enc)
        return ciphertext

    def transaction2(adminPubKey, SID):
        bSID = SID.encode()
        key = b"4u7x!A%D*G-KaPdSgVkXp2s5v8y/B?E("
        sign = private_key.sign(
            bSID,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        p = poly1305.Poly1305.generate_tag(key, sign)
        enc = adminPubKey.encrypt(
            p,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        ciphertext = base64.b64encode(enc)
        return ciphertext

    #Run All
    checkSID(SID)
    t1 = transaction1(SID)
    t2 = transaction2(adminPubKey, SID)
    SaveT(t1, t2)
    
conn.close ()