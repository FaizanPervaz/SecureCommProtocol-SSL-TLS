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

def perform_dh_key_exchange(client_private_key, server_public_key, parameters):
    shared_key = client_private_key.exchange(server_public_key)
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
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 12345))

    private_key, public_key, parameters = generate_dh_parameters()  # Retrieve DH parameters

    if parameters is None:
        return  # Terminate if DH parameters are not loaded

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="ca.crt")

    # Load the client's certificate and private key
    context.load_cert_chain(certfile="client.crt", keyfile="client.key")

    ssl_connection = context.wrap_socket(client, server_hostname="localhost")

    # Serialize and send the client's public key
    client_public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    ssl_connection.send(client_public_key_pem)

    # Perform DH key exchange
    server_public_key_pem = ssl_connection.recv(4096)
    server_public_key = serialization.load_pem_public_key(server_public_key_pem)
    shared_key = perform_dh_key_exchange(private_key, server_public_key, parameters)

    # Inside the client's message sending loop
    while True:
        message = input("Enter a message (type 'exit' to quit): ")
        if message == 'exit':
            ssl_connection.send(message.encode())
            break

        # Encrypt and send the message
        encrypted_message = encrypt_message(shared_key, message.encode())
        ssl_connection.send(encrypted_message)

        response = ssl_connection.recv(4096)
        decrypted_response = decrypt_message(shared_key, response)
        print("Received:", decrypted_response.decode())


    ssl_connection.close()

if __name__ == "__main__":
    main()
