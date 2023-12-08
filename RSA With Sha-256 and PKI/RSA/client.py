import socket
import ssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

#Configurating Client
HOST = '127.0.0.1'
PORT = 12345

# Creating a socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Wraping the socket with SSL
    client_socket = ssl.wrap_socket(client_socket)

    # Connecting to the server
    client_socket.connect((HOST, PORT))

   
    menu = client_socket.recv(1024).decode()
    print(menu)

    
    choice = ''
    while choice not in ['1', '2', '3']:
        choice = input("Enter anything to run")
    client_socket.send(choice.encode())

    if choice == '2':
        # Handle RSA encryption
        rsa_message = client_socket.recv(1024).decode()
        print(rsa_message)
        # Implement RSA logic here
        key = RSA.generate(2048)

        client_public_key = key.publickey()
        client_private_key = key
        client_socket.send(client_public_key.exportKey())    
        server_public_key = RSA.import_key(client_socket.recv(1024))
        

        while True:
            ciphertext = client_socket.recv(1024)
            decipher = PKCS1_OAEP.new(client_private_key)
            decrypted_message = decipher.decrypt(ciphertext)
            print("Received Encrypted Message: ", ciphertext)
            print("Decrypted Message: ", decrypted_message.decode())

            message = input("Client: Enter a message (or 'exit' to quit): ")
            if message == 'exit':
                client_socket.send(b"Client has exited.")
                break
            message_bytes = message.encode('utf-8')
            cipher = PKCS1_OAEP.new(server_public_key)
            ciphertext = cipher.encrypt(message_bytes)

            client_socket.send(ciphertext)
        
           

    elif choice == '3':
        message = client_socket.recv(1024).decode()
        print(message)

finally:
    # Closing the client socket
    client_socket.close()