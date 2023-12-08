import socket
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

def Gen_RSA():
    p_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    return p_key

def Gen_x25519_key():
    pr_key = X25519PrivateKey.generate()
    pub_key = pr_key.public_key()
    return pr_key, pub_key

def load_x25519_pubkey(data):
    return X25519PublicKey.from_public_bytes(data)

def exchange_x25519_pubkey(server_socket, pub_key):
    pub_key_bytes = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    server_socket.send(pub_key_bytes)

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 12345))

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile="server.crt")
    ssl_connection = context.wrap_socket(client, server_hostname="localhost")

    pr_key = Gen_RSA()
    pr_key_x25519, pub_key_x25519 = Gen_x25519_key()
    exchange_x25519_pubkey(ssl_connection, pub_key_x25519)

    while True:
        msg = input("Enter a message (type 'exit' to exit): ")
        if msg == 'exit':
            ssl_connection.send(msg.encode())
            break

        # Encrypt the message
        x25519_pub_key = ssl_connection.recv(2048)
        pub_key = X25519PublicKey.from_public_bytes(x25519_pub_key)
        shared_key = pr_key_x25519.exchange(pub_key)
        ciphertext = shared_key.encrypt(msg.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        ssl_connection.send(ciphertext)

        response = ssl_connection.recv(4096)

        shared_key = pr_key_x25519.exchange(pub_key)
        decrypted_response = shared_key.decrypt(response, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        print("Got: ", decrypted_response.decode())

    ssl_connection.close()

if __name__ == "__main__":
    main()