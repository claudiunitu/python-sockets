import socket
import ssl
import errno
import sys
import time

import threading

from helper_functions import receiveBytes, sendBytes


SERVER_HOST_NAME = socket.gethostname()
SERVER_HOST_IP = socket.gethostbyname(SERVER_HOST_NAME)
SERVER_PORT = 4449
CONNECTIONS_TO_ACCEPT_AT_ONCE = 5
USE_TLS = True

def threadedConnectionHandler(remoteSocket: socket.socket, lock: threading.Lock):

    while True:

        print("Getting data...")

        messageBytes: bytes = b""
        messageDecoded: str = ""

        try:
            messageBytes = receiveBytes(remoteSocket)  # this blocks
            messageDecoded = messageBytes.decode('utf-8')
            print(messageDecoded)
            sendBytes(remoteSocket, b'SERVER: I have received your message')
        except Exception as e:
            print("Failed to receive bytes. Will close connection to remote socket. " + str(e))
            remoteSocket.close()
            break

        
        

def threadedServerListenerHandler(serverSocket: socket.socket, maxSimultaneousConnections: int, lock: threading.Lock):
    try:
        serverSocket.listen(maxSimultaneousConnections)
    except Exception as e:
        print(str(e))

        serverSocket.close()
        sys.exit("Server closed.")

    chosenSocket: socket.socket = serverSocket

    if USE_TLS:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="./server-security/cert.pem", keyfile="./server-security/key.pem")
        chosenSocket = context.wrap_socket(serverSocket, server_side=True)

    while True:
        try:
            clientSocket, clientAddr = chosenSocket.accept()  # this blocks
            print(f"New client connected: {clientAddr}")
            threading.Thread(target=threadedConnectionHandler, args=(clientSocket,lock), daemon=True).start()
            
        except Exception as e:
            print("New client failed to connect. " + str(e))
            continue


print("Starting server...")

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    serverSocket.bind((SERVER_HOST_IP, SERVER_PORT))
except socket.error as e:

    if e.errno == errno.EADDRINUSE:
        print("Port: " + str(SERVER_PORT) + " is already in use.")
    else:
        print(str(e))

    serverSocket.close()
    sys.exit("Server closed.")

lock = threading.Lock()

threading.Thread(target=threadedServerListenerHandler, args=(serverSocket, CONNECTIONS_TO_ACCEPT_AT_ONCE, lock), daemon=True).start()

print("Listening on: " + SERVER_HOST_IP + ", port: " + str(SERVER_PORT))


while True:
    try:
        time.sleep(1000)
    except KeyboardInterrupt:
        sys.exit()
