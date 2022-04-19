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
            broadcast(f'El usuario {user} ha dejado la sesión'.encode('utf-8'))
            break

def accept_connections():
    while True:
        client, address = server.accept()
        print(f'{str(address)} Se conectó con éxito.')
        client.sendall('Ingrese usuario: '.encode('utf-8'))
        user = recvall(client).decode('utf-8')
        users.append(user)
        clients.append(client)
        print(f'Usuario {user} correctamente registrado.')
        broadcast(f'El usuario {user} se ha unido a la sesión.'.encode('utf-8'))
        if len(clients) == 1:
            client.sendall('\n Sesión iniciada correctamente.'.encode('utf-8'))
        else:
            client.sendall('\n Conectado con éxito a la sesión.'.encode('utf-8'))
        
        thread = threading.Thread(target=handle,args=(client,))
        thread.start()


import threading
import socket
import argparse

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
client, address = server.accept()
print(f'{str(address)} Se conectó con éxito.')
client.sendall('Ingrese usuario: '.encode('utf-8'))
user = recvall(client).decode('utf-8')
users.append(user)
clients.append(client)
print(f'Primer usuario {user} correctamente registrado.')
client.sendall('\n Sesión iniciada correctamente.'.encode('utf-8'))
respuesta_llave_sim = recvall(client).decode('utf-8')
print(respuesta_llave_sim)
thread = threading.Thread(target=handle,args=(client,))
thread.start()


accept_connections()