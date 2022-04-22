#def encrypt_AES(message,key):    
   # key1 = generate_sim_key()
  #  cipher = AES.new(key1, AES.MODE_EAX,nonce=b'0')
 #   CT = cipher.encrypt(message)
#    return CT

def recvall(sock):
    BUFF_SIZE = 1024
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            break
    return data

def broadcast(message):
    print(message)
    for client in clients:
        client.sendall(message)

def handle(client):
    while True:
        try:
            message = recvall(client)
            broadcast(message)
        except:
            index = clients.index(client)
            clients.remove(client)
            user = users[index]
            users.remove(user)
            broadcast(f'El usuario {user} ha dejado la sesión'.encode('latin1'))
            break

def accept_connections():
    while True:
        client, address = server.accept()
        print(f'{str(address)} Se conectó con éxito.')
        client.sendall('Ingrese usuario: '.encode('latin1'))
        user = recvall(client).decode('latin1')
        users.append(user)
        clients.append(client)
        print(f'Usuario {user} correctamente registrado.')
        broadcast(f'El usuario {user} se ha unido a la sesión.'.encode('latin1'))
        thread = threading.Thread(target=handle,args=(client,))
        thread.start()



import threading
import socket
import argparse
import time

parser = argparse.ArgumentParser(description='Proyecto Final Seguridad Informática - Brucelee Campos - CINVESTAV')
parser.add_argument("-p", "--port", help="Puerto del Servidor")
args = parser.parse_args()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
host = s.getsockname()[0]
port = int(args.port)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host,port))
server.listen()
clients = []
users = []
print("Servidor montado en la dirección: "+ host + " en el puerto: "+str(port))
print('El servidor esta esperando la primera conexión...')

#respuesta_llave_sim = recvall(client).decode('latin1')



accept_connections()