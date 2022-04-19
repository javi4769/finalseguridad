def broadcast(message):
    for client in clients:
        client.send(message)

def handle(client):
    while True:
        try:
            message = client.recv(1024)
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
        client.send('Ingrese usuario: '.encode('utf-8'))
        user = client.recv(1024).decode('utf-8')
        users.append(user)
        clients.append(client)
        print(f'Usuario {user} correctamente registrado.')
        broadcast(f'El usuario {user} se ha unido a la sesión.'.encode('utf-8'))
        if len(clients) == 1:
            client.send('\n Sesión iniciada correctamente.'.encode('utf-8'))
            key = client.recv(1024)
            print(key)
            client.send('Ok cuh'.encode('utf-8'))
        else:
            client.send('\n Conectado con éxito a la sesión.'.encode('utf-8'))
        
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
print('El servidor esta esperando conexiones...')


accept_connections()