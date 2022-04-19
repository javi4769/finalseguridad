import socket 
import threading 
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#client.connect(('148.247.204.90',5004))
client.connect(('192.168.1.70',80))
user = input('Ingrese un nombre de usuario: ')
def receive():
    while(True):
        try:
            message = client.recv(1024).decode('utf-8')
            if message == 'Ingrese usuario: ':
                client.send(user.encode('utf-8'))
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

receive_thread = threading.Thread(target=receive)
receive_thread.start()
write_thread = threading.Thread(target=write)
write_thread.start()