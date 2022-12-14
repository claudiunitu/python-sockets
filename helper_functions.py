from socket import socket
import threading
import sys
from constants import DATA_BUFF_SIZE, HEADER_LENGTH


def sendBytesChunkByChunk(socket: socket, bytesToSend: bytes, chunkBuffSize: int):
    bytesToSendLength = len(bytesToSend)
    bytesSentCount = 0
    try:
        while bytesSentCount < bytesToSendLength:
            bytesSentCount += socket.send(bytesToSend[bytesSentCount : bytesSentCount + chunkBuffSize])
    except Exception as e:
        raise e


def receiveBytesChunkByChunk(socket: socket, chunkBuffSize: int, messageSizeBytes: int) -> bytes:

    '''receive bytes respecting the buffer size
    returned bytes length may exceed the specified messageSizeBytes if the buffer size is bigger than messageSizeBytes 
    and the remote socket sends more data than expected in one single bufferSize range'''

    receivedBytes: bytearray = bytearray()
    while len(receivedBytes) < messageSizeBytes:
        chunk: bytes
        try:
            chunk = socket.recv(chunkBuffSize)  # this blocks
        except Exception as e:
            raise e
        if chunk:
            receivedBytes.extend(chunk)
        else:
            raise Exception(
                'Error while receiving bytes chunk by chunk. Most probably the remote socket was closed')
    return bytes(receivedBytes)



def encodeHeaderForPayload(bytesToSend: bytes) -> bytes:
    ''' header will be of form: "xxxx[...]              "
    where xxxx will be the length of the message to which it is attached to
    and the white spaces are the padding until the header known fixed length it is achieved'''
    bytesToSendCount = len(bytesToSend)
    headerBytearray = bytearray(
        f"{bytesToSendCount:<{HEADER_LENGTH}}", 'utf-8')
    return bytes(headerBytearray)


# decoded header will be a tuple where the first item represents the length of the message to which the header is attached to
def decodeHeader(header: bytes) -> tuple[int]:
    try:
      messageLength = int(header.decode('utf-8'))
      return (messageLength,)
    except Exception as e:
      print("ERROR: Cannot decode header.")
      raise e


def sendBytes(socket: socket, bytesToSend: bytes):

    headerBytes = encodeHeaderForPayload(bytesToSend)
    fullBytearray = bytearray(headerBytes)
    fullBytearray.extend(bytesToSend)

    try:
        sendBytesChunkByChunk(
            socket, bytes(fullBytearray), DATA_BUFF_SIZE)
    except Exception as e:
        raise e


def receiveBytes(socket: socket) -> bytes:
    messageBodyLength: int
    transmissionRawBytes: bytearray = bytearray()
    try:
        # try to figure out the header contents from the first bytes of the received information
        while len(transmissionRawBytes) < HEADER_LENGTH:
            chunk = receiveBytesChunkByChunk(socket, DATA_BUFF_SIZE, HEADER_LENGTH)
            transmissionRawBytes.extend(chunk)
        headerRawBytes = bytes(transmissionRawBytes[:HEADER_LENGTH])
        (messageBodyLength,) = decodeHeader(headerRawBytes)

        # receive the rest of the information using the information provided by the header if needed
        remainingBytesToReceiveCount = (messageBodyLength + HEADER_LENGTH) - len(transmissionRawBytes)
        if remainingBytesToReceiveCount > 0:
            chunk = receiveBytesChunkByChunk(socket, DATA_BUFF_SIZE, remainingBytesToReceiveCount)
            transmissionRawBytes.extend(chunk)
        return bytes(transmissionRawBytes[HEADER_LENGTH:])
    except Exception as e:
        raise e

