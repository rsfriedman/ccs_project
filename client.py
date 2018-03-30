#!/usr/bin/python3

# base client.py from https://www.tutorialspoint.com/python3/python_networking.htm

import socket

# create a socket object
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# get local machine name
host = socket.gethostname()

port = 9999

# connection to hostname on the port.
clientSocket.connect((host, port))
print("Whoa!" + "\n" + "We've connected to the server!" + "\n")
msg = ""
with open('downloaded_file.txt', 'wb') as file:
    while True:
        print('receiving data...')
        data = clientSocket.recv(1024)      # Receive no more than 1024 bytes
        msg = msg + data.decode('ascii')    # Building the message
        if not data:
            break
        file.write(data)                    #writing data to new file

file.close()
clientSocket.close()
print("\n" + "Here is the data we've recieved: " + "\n" + msg)
print('Check contents of "downloaded_file"')

#todo client file upload
