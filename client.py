def recvall(sock):
    BUFF_SIZE = 1024
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            break
    return data

def get_pair_keys():
    keyPair = RSA.generate(3072)
    pubKey = keyPair.publickey()
    pubKeyPEM = pubKey.exportKey()
    Kpub = (pubKeyPEM.decode('latin1'))
    privKeyPEM = keyPair.exportKey()
    Kpriv = (privKeyPEM.decode('latin1'))
    return Kpub, Kpriv

def encrypt_AES(message):    
    key1 = generate_sim_key()
    cipher = AES.new(key1, AES.MODE_EAX,nonce=b'0')
    CT = cipher.encrypt(message)
    return CT

def decrypt_AES(message):    
    key1 = generate_sim_key()
    cipher = AES.new(key1, AES.MODE_EAX,nonce=b'0')
    PT = cipher.decrypt(message)
    return PT

def generate_sim_key():
    password = b'xd'
    salt = b'xc'
    key = PBKDF2(password, salt, 32, 1000000, hmac_hash_module=SHA256)
    return key

def receive():
    First = True
    while(True):
        try:
            f = False
            message = recvall(client)
            #print(type(message))
            xd = message.decode('latin1')
            if "El usuario" in xd:
                f = True
                print(xd)

            message = decrypt_AES(message)
            message = message.decode('latin1')
            #print(type(message))
            #message = decrypt_AES(bytes(message,'latin1'))
            #print(type(message))
            if First:
                client.sendall(user.encode('latin1'))
                First = False
            elif ((user + ":") not in  message) and (f == False):
                print(message)
        except:
            print('Ha ocurrido un error.')
            client.close()
            break
def write():
    while(True):
        message = input("")
        if message == "clear":
            os.system("clear")
        else:
            now = datetime.now()
            current_time = now.strftime("%H:%M:%S")
            message = "["+current_time+"] "+user +": " + message
            message = encrypt_AES(bytes(message,'latin1'))
            client.sendall(message)

# Importamos bibliotecas necesarias
import socket 
import threading
import argparse
import os
import hashlib
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import MD5
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import hmac
import time
import gc
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
import binascii
from Crypto.Cipher import PKCS1_OAEP
import getpass
from datetime import datetime


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
parser = argparse.ArgumentParser(description='Proyecto Final Seguridad Inform??tica - Brucelee Campos - CINVESTAV')
parser.add_argument("-s", "--server", help="IP del Servidor")
parser.add_argument("-u", "--user", help="Nombre de Usuario")
parser.add_argument("-p", "--port", help="Puerto del Servidor")

args = parser.parse_args()
client.connect((args.server,int(args.port)))
user = args.user
#keys = get_pair_keys()
#kpub = keys[0]
#kpriv = keys[1]
receive_thread = threading.Thread(target=receive)
receive_thread.start()
write_thread = threading.Thread(target=write)
write_thread.start()