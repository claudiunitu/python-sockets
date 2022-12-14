import socket
import ssl

from helper_functions import sendBytes


SERVER_SOCKET_HOST = "192.168.0.104"
SERVER_SOCKET_PORT = 4449
USE_TLS = True

print("Starting client...")

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


chosenSocket: socket.socket = clientSocket

if USE_TLS:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode=ssl.CERT_NONE

    # context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # context.load_cert_chain(certfile="./client-security/cert.pem", keyfile="./client-security/key.pem")
    # context.load_verify_locations('./server-security/cert.pem')
    chosenSocket = context.wrap_socket(clientSocket, server_hostname=SERVER_SOCKET_HOST)


    

try:
    print(
        f"Connecting to server {SERVER_SOCKET_HOST} on port {SERVER_SOCKET_PORT}...")
    chosenSocket.connect((SERVER_SOCKET_HOST, SERVER_SOCKET_PORT))
except Exception as e:
    print("Error while trying to connect to remote socket.")
    raise e

while True:

    message = 'Lorem ipsum dolor sit amet.'

    print("Sending message data to remote socket...")
    try:

        sendBytes(chosenSocket, bytes(message, "utf-8"))
    except Exception as e:
        print("Failed sending message data to remote socket!")
        raise e
    # clientSocket.close()
    input('Press enter')
    
