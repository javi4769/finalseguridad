def recvall(sock):
    BUFF_SIZE = 1024
    data = b''
    try:
        while True:
            part = sock.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
    except: 
        pass
    return data

def encrypt_AES(message):    
    key1 = generate_sim_key()
    cipher = AES.new(key1, AES.MODE_EAX,nonce=b'0')
    CT = cipher.encrypt(bytes(message,'ascii'))
    return CT

def decrypt_AES(CT):    
    key1 = generate_sim_key()
    cipher = AES.new(key1, AES.MODE_EAX,nonce=b'0')
    PT = cipher.decrypt(message)
    return PT

def get_pair_keys():
    keyPair = RSA.generate(3072)
    pubKey = keyPair.publickey()
    pubKeyPEM = pubKey.exportKey()
    Kpub = (pubKeyPEM.decode('ascii'))
    privKeyPEM = keyPair.exportKey()
    Kpriv = (privKeyPEM.decode('ascii'))
    return Kpub, Kpriv
    
def generate_sim_key():
    #password = os.urandom(16)
    password = b"Hola"

    #salt = os.urandom(16)
    salt = b"Soy Bruce"

    key = PBKDF2(password, salt, 32, 1000000, hmac_hash_module=SHA256)
    return key

def receive():
    while(True):
        try:
            message = recvall(client).decode('ascii')
            if message == 'Ingrese usuario: ':
                print("Me creo el usuario")
                client.sendall(user.encode('ascii'))         
            else:
                #resp = decrypt_AES(message.encode('ascii'))
                #print(resp.decode('ascii'))
                print(message)
        except:
            print('Ha ocurrido un error.')
            client.close()
            break
def write():
    #client.sendall(kpub.encode('ascii'))
    while(True):
        message = input("")
        if message == "clear":
            os.system("clear")
        else:
            now = datetime.now()
            current_time = now.strftime("%H:%M:%S")
            message = "["+current_time+"] "+user +": " + message
            message = encrypt_AES(message)
            client.sendall(message)

# Importamos bibliotecas necesarias
import socket 
import threading
import getpass
import argparse
import os
import hashlib
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Cipher import DES3

import hmac
import time
import gc
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
import binascii
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
parser = argparse.ArgumentParser(description='Proyecto Final Seguridad Informática - Brucelee Campos - CINVESTAV')
parser.add_argument("-s", "--server", help="IP del Servidor")
parser.add_argument("-u", "--user", help="Nombre de Usuario")
parser.add_argument("-p", "--port", help="Puerto del Servidor")
args = parser.parse_args()
client.connect((args.server,int(args.port)))
user = args.user
keys = get_pair_keys()
kpub = keys[0]
kpriv = keys[1]
receive_thread = threading.Thread(target=receive)
receive_thread.start()
write_thread = threading.Thread(target=write)
write_thread.start()