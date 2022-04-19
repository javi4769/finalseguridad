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


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
parser = argparse.ArgumentParser(description='Proyecto Final Seguridad Informática - Brucelee Campos - CINVESTAV')
parser.add_argument("-s", "--server", help="IP del Servidor")
parser.add_argument("-u", "--user", help="Nombre de Usuario")
parser.add_argument("-p", "--port", help="Puerto del Servidor")

args = parser.parse_args()
client.connect((args.server,int(args.port)))
user = args.user

def receive():
    while(True):
        try:
            message = client.recv(1024).decode('utf-8')
            if message == 'Ingrese usuario: ':
                client.send(user.encode('utf-8'))      
            elif message == '\n Sesión iniciada correctamente.':
                print(message)
                key = generate_sim_key()        
                client.send(key)
            elif message == '\n Conectado con éxito a la sesión.':
                print(message)
            else:
                print(message)
        except:
            print('Ha ocurrido un error.')
            client.close()
            break
def write():
    while(True):
        message = f'{user}: {input("")}'
        client.send(message.encode('utf-8'))

def generate_sim_key():
    password = os.urandom(16)
    salt = os.urandom(16)
    key = PBKDF2(password, salt, 32, 1000000, hmac_hash_module=SHA256)
    return key

receive_thread = threading.Thread(target=receive)
receive_thread.start()
write_thread = threading.Thread(target=write)
write_thread.start()