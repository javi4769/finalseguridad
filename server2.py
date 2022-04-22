def recvall(sock):
    BUFF_SIZE = 1024
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            break
    return data
import socket, select, queue, argparse

parser = argparse.ArgumentParser(description='Proyecto Final Seguridad Informática - Brucelee Campos - CINVESTAV')
parser.add_argument("-p", "--port", help="Puerto del Servidor")
args = parser.parse_args()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
host = s.getsockname()[0]
port = int(args.port)
SERVERPORT = port
print("Corriendo en el host " + host + " en el puerto "+ str(SERVERPORT)+ ".")
print("Aceptando conexiones...")

svrsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
svrsock.setblocking(0)
svrsock.bind((host, SERVERPORT))
svrsock.listen(16)
client_queues = {}
write_ready=[] # we'll update this for clients only that have things in the queue
while list(client_queues) + [svrsock] :
  readable, writable, exceptional = select.select(list(client_queues) + [svrsock] , write_ready, [])
  for rd in readable:
    if rd is svrsock: # reading listening socket == accepting connection
      conn, addr = svrsock.accept()
      print("Connection from {}".format(addr))
      conn.sendall('Ingrese usuario: '.encode('ascii'))
      
      conn.setblocking(0)
      client_queues[conn] = queue.Queue()
    else:
      data = recvall(rd)
      if data:
        #if "+" in data:
          #llave = conn.sendall('enviar_llave'.encode('ascii'))
        # TODO: send to all queues
        print("Message from {}".format(rd.getpeername()))
        print(data)
        for sock, q in client_queues.items(): 
          q.put(data)
          if sock not in write_ready:
            write_ready.append(sock)
  for rw in writable:
    try:
      data = client_queues[rw].get_nowait()
      rw.sendall(data)
    except queue.Empty:
      write_ready.remove(rw)
      continue