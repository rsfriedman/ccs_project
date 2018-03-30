#!/usr/bin/python3


# base server.py from https://www.tutorialspoint.com/python3/python_networking.htm

import socket

# create a socket object
serverSocket = socket.socket(
    socket.AF_INET, socket.SOCK_STREAM)

# get local machine name
host = socket.gethostname()

port = 9999

# bind to the port
serverSocket.bind((host, port))

# queue up to 5 requests
serverSocket.listen(5)
print("Server listening...")

while True:
    # establish a connection
    clientSocket, addr = serverSocket.accept()
    print("Got a connection from %s" % str(addr))

    #transfer file (download)
    filename = 'test.txt'
    file = open(filename, 'rb')
    file_line = file.read(1024)
    while (file_line):
        clientSocket.send(file_line)
        print('Sent ', file_line)
        file_line = file.read(1024)
        msg = "\r\n" + 'Thank you for connecting' + "\r\n"
        clientSocket.send(msg.encode('ascii'))
    file.close()
    clientSocket.close()

#todo server recieves file from client
