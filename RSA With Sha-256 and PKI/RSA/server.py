import socket
import ssl
from Crypto.Cipher import AES
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

#Configurating Server 
HOST = '127.0.0.1'
PORT = 12345
CERTIFICATE_FILE = 'server.crt'
PRIVATE_KEY_FILE = 'server.key'

# Creating a Socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Wrapping the socket with SSL to make it secure
    server_socket = ssl.wrap_socket(server_socket, keyfile=PRIVATE_KEY_FILE, certfile=CERTIFICATE_FILE, server_side=True)

    # Binding the socket to the host and port
    server_socket.bind((HOST, PORT))

    # Listening for connections
    server_socket.listen(5)

    print(f"Server is listening on {HOST}:{PORT}...")

    # Implement Diffie-Hellman logic here
    p = 23  
    g = 9  

    while True:
        
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")

        # Send a menu for encryption selection
        menu = "RSA Encryption Technique\n"
        client_socket.send(menu.encode())

        # Receive the client's choice
        choice = ''
        while choice not in ['1', '2', '3']:
            choice = client_socket.recv(1024).decode()

        if choice == '2':
       
            client_socket.send(b"RSA Begun")
            # RSA 
            key = RSA.generate(2048)

            server_public_key = key.publickey()
            server_private_key = key
            client_public_key = RSA.import_key(client_socket.recv(1024))
            client_socket.send(server_public_key.export_key())
            print(server_public_key.export_key())
            while True:
                message = input("Server: Enter a message (or 'exit' to quit): ")
                if message == 'exit':
                    client_socket.send(b"Server has exited.")
                    break
                message_bytes = message.encode('utf-8')
                cipher = PKCS1_OAEP.new(client_public_key)
                ciphertext = cipher.encrypt(message_bytes)

                client_socket.send(ciphertext)

                ciphertext = client_socket.recv(1024)
                decipher = PKCS1_OAEP.new(server_private_key)
                decrypted_message = decipher.decrypt(ciphertext)
                print("Received Encrypted Message: ", ciphertext)
                print("Decrypted Message: ", decrypted_message.decode())

                
        elif choice == '3':
            client_socket.send(b"Bye!")
            client_socket.close()
            break

finally:
    #Closing the socket
    server_socket.close()