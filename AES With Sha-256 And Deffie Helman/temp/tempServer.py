import socket
import ssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key, parameters  # Return DH parameters

def perform_dh_key_exchange(server_private_key, client_public_key, parameters):
    shared_key = server_private_key.exchange(client_public_key)
    return shared_key

def load_dh_params():
    try:
        with open("dhparams.pem", "rb") as file:
            dh_params = serialization.load_pem_parameters(file.read())
    except Exception as e:
        print("Error loading DH parameters:", e)
        return None
    return dh_params

def encrypt_message(shared_key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message + b' ' * (16 - len(message) % 16)  # PKCS7 padding
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return iv + encrypted_message

def decrypt_message(shared_key, encrypted_data):
    iv, encrypted_message = encrypted_data[:16], encrypted_data[16:]
    cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 12345))
    server.listen(1)

    private_key, public_key, parameters = generate_dh_parameters()  # Retrieve DH parameters

    if parameters is None:
        return  # Terminate if DH parameters are not loaded

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    # Load the server's certificate and private key
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    # Load the CA certificate
    context.load_verify_locations(cafile="ca.crt")

    while True:
        print("Waiting for a connection...")
        client, addr = server.accept()
        ssl_connection = context.wrap_socket(client, server_side=True)

        print("Connection established with", addr)

        # Serialize and send the server's public key
        server_public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        ssl_connection.send(server_public_key_pem)

        # Perform DH key exchange
        client_public_key_pem = ssl_connection.recv(4096)
        client_public_key = serialization.load_pem_public_key(client_public_key_pem)
        shared_key = perform_dh_key_exchange(private_key, client_public_key, parameters)

        # Inside the server's message sending loop
        while True:
            encrypted_message = ssl_connection.recv(4096)

            if not encrypted_message:
                break

            decrypted_message = decrypt_message(shared_key, encrypted_message)
            print("Received:", decrypted_message.decode())

            response = input("Enter a response: ")  # Prompt for server response
            if response == 'exit':
                ssl_connection.send(response.encode())
                break

            # Encrypt and send the response
            encrypted_response = encrypt_message(shared_key, response.encode())
            ssl_connection.send(encrypted_response)


        ssl_connection.close()
        print("Connection closed with", addr)

if __name__ == "__main__":
    main()
