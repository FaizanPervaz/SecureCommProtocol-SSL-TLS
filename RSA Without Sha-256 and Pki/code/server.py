import socket
import ssl
from Crypto.Cipher import AES
import hashlib


server_host = '0.0.0.0'  
server_port = 443  


server_cert = 'D:\\University\\Semester 7\\Information Security\\Assignment 2\\RSA\\server\\server-cert.pem'
server_key = 'D:\\University\\Semester 7\\Information Security\\Assignment 2\\RSA\\server\\server-key.pem'


def unpad(plaintext):
    padding_length = plaintext[-1]
    return plaintext[:-padding_length]


def decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    decrypted_data = unpad(decrypted_data)
    return decrypted_data


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((server_host, server_port))
server_socket.listen(1)

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=server_cert, keyfile=server_key)

print(f"Listening for connections on {server_host}:{server_port}...")

while True:
    client_socket, client_addr = server_socket.accept()
    with context.wrap_socket(client_socket, server_side=True) as secure_socket:
        print(f"Accepted connection from {client_addr}")
        
        data = secure_socket.recv(1024)
        if not data:
            break
        
        
        sha256_hash = data[:32]  
        key = data[32:48]  
        ciphertext = data[48:]
        
      
        calculated_sha256_hash = hashlib.sha256(decrypt(ciphertext, key)).digest()
        
        if sha256_hash == calculated_sha256_hash:
            print("SHA-256 Hash Matched. Data is authentic.")
        else:
            print("SHA-256 Hash Mismatch. Data may be compromised.")
        
        print(f"Received encrypted string from client: {ciphertext}")
        decrypted_text = decrypt(ciphertext, key)
        print(f"Received and decrypted data from client: {decrypted_text.decode('utf-8')}")
        
        
        response = b'Response from server'
        secure_socket.send(response)

server_socket.close()
