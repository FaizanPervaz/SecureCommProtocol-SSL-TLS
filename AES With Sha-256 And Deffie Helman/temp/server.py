import socket
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

def Gen_RSA():
    p_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    return p_key

def load_x25519_pubkey(data):
    return X25519PublicKey.from_public_bytes(data)

def exchange_x25519_pubkey(client_socket, pub_key):
    pub_key_bytes = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    client_socket.send(pub_key_bytes)

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 12345))
    server.listen(1)

    Connection, addr = server.accept()
    print("Connection being established with: ", addr)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    client_pb_key = Gen_RSA()
    pr_key = Gen_RSA()
    pr_key_x25519 = X25519PrivateKey.generate()
    pr_key_pub_x25519 = pr_key_x25519.public_key()

    ssl_connection = context.wrap_socket(Connection, server_side=True)

    while True:
        data = ssl_connection.recv(4096)
        if not data:
            break

        # Key exchange using x25519
        x25519_pub_key = load_x25519_pubkey(data)
        shared_key = pr_key_x25519.exchange(x25519_pub_key)

        de_data = b''
        while True:
            data = ssl_connection.recv(4096)
            if not data:
                break
            de_data += data

        if not de_data:
            break

        # Decrypt the message
        cipher = serialization.load_pem_private_key(de_data, password=None, backend=default_backend())
        decrypted_message = cipher.decrypt(de_data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        print("Received: ", decrypted_message.decode())

        res = input("Reply to client (type 'exit' to exit): ")

        if res == 'exit':
            ssl_connection.send(res.encode())
            break

        # Encrypt the response message
        x25519_pub_key = pr_key_pub_x25519.public_bytes(Encoding.Raw, PublicFormat.Raw)
        pub_key = X25519PublicKey.from_public_bytes(x25519_pub_key)
        shared_key = pr_key_x25519.exchange(pub_key)
        ciphertext = shared_key.encrypt(res.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        ssl_connection.send(ciphertext)

    ssl_connection.close()

if __name__ == "__main__":
    main()