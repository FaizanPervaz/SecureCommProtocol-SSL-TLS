import socket
import ssl
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import tkinter as tk


server_host = 'localhost'
server_port = 443 


ca_cert = 'D:\\University\\Semester 7\\Information Security\\Assignment 2\\RSA\\ca\ca-cert.pem'
client_cert = 'D:\\University\\Semester 7\\Information Security\\Assignment 2\\RSA\\client\client-cert.pem'
client_key = 'D:\\University\\Semester 7\\Information Security\\Assignment 2\\RSA\\client\client-key.pem'

def pad(plaintext):
    padding_length = 16 - (len(plaintext) % 16)
    padding = bytes([padding_length] * padding_length)
    return plaintext + padding


def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = pad(plaintext)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def send_message():
    input_string = entry.get()  
    key = get_random_bytes(16)  
    ciphertext = encrypt(input_string.encode('utf-8'), key)

   
    sha256_hash = hashlib.sha256(input_string.encode('utf-8')).digest()

    print("SHA-256 Hash of the plaintext:", sha256_hash)

    print("Encrypted data (ciphertext) to be sent to the server:", ciphertext)

    
    secure_socket.send(sha256_hash + key + ciphertext)

   
    response = secure_socket.recv(1024)
    if response:
        print("Received response from the server:", response.decode('utf-8'))


window = tk.Tk()
window.title("Secure Client")


heading_label = tk.Label(window, text="Enter text below:")
heading_label.pack()


entry = tk.Entry(window)
entry.pack()


send_button = tk.Button(window, text="Send", command=send_message)
send_button.pack()

try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(ca_cert)  

    if client_cert and client_key:
        context.load_cert_chain(certfile=client_cert, keyfile=client_key)

    client_socket.connect((server_host, server_port))
    with context.wrap_socket(client_socket, server_hostname=server_host) as secure_socket:
        window.mainloop() 

except Exception as e:
    print(f"Error: {e}")
finally:
    client_socket.close()
