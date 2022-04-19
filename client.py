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
    Kpub = (pubKeyPEM.decode('utf-8'))
    privKeyPEM = keyPair.exportKey()
    Kpriv = (privKeyPEM.decode('utf-8'))
    return Kpub, Kpriv
    
def generate_sim_key():
    password = os.urandom(16)
    salt = os.urandom(16)
    key = PBKDF2(password, salt, 32, 1000000, hmac_hash_module=SHA256)
    return key

def receive():
    while(True):
        try:
            message = recvall(client).decode('utf-8')
            if message == 'Ingrese usuario: ':
                client.sendall(user.encode('utf-8'))   
            elif message == '\n Sesión iniciada correctamente.':
                llave_sim = generate_sim_key()
                respuesta = ("El primer cliente generó la llave de sesión")
                client.sendall(respuesta.encode('utf-8'))   

            elif (user + ":") not in  message:
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
            message = user +": " + message 
            client.sendall(message.encode('utf-8'))

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


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
parser = argparse.ArgumentParser(description='Proyecto Final Seguridad Informática - Brucelee Campos - CINVESTAV')
parser.add_argument("-s", "--server", help="IP del Servidor")
parser.add_argument("-u", "--user", help="Nombre de Usuario")
parser.add_argument("-p", "--port", help="Puerto del Servidor")

args = parser.parse_args()
client.connect((args.server,int(args.port)))
user = args.user
keys = get_pair_keys()
print(keys)
kpub = keys[0]
kpriv = keys[1]

receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()