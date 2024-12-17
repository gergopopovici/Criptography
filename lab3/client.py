import socket
import json
import sys
from threading import Thread, Event
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

KEY_SERVER_HOST = 'localhost'
KEY_SERVER_PORT = 8000

def log(message):
    print(f"[LOG] {message}")

exit_event = Event()

def generate_rsa_key_pair():
    return RSA.generate(2048)

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return cipher.iv, ciphertext

def decrypt_message(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def rsa_encrypt_message(public_key, message):
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    return cipher_rsa.encrypt(message)

def rsa_decrypt_message(private_key, encrypted_message):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_message)

# Register Public Key with KeyServer
def register_with_keyserver(client_id, public_key):
    log(f"Registering with KeyServer as {client_id}")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((KEY_SERVER_HOST, KEY_SERVER_PORT))
            request = {
                "action": "register",
                "client_id": client_id,
                "public_key": public_key.decode()
            }
            sock.sendall(json.dumps(request).encode())
            response = sock.recv(1024).decode()
            log(f"KeyServer response: {response}")
    except Exception as e:
        log(f"Error during registration: {e}")

def get_public_key(target_id):
    log(f"Requesting public key for {target_id}")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((KEY_SERVER_HOST, KEY_SERVER_PORT))
            request = {"action": "get_key", "target_id": target_id}
            sock.sendall(json.dumps(request).encode())
            response = sock.recv(4096).decode()
            return json.loads(response).get("public_key")
    except Exception as e:
        log(f"Error getting public key: {e}")
        return None

def key_exchange(sock, rsa_key, peer_public_key):
    try:
        secret = get_random_bytes(16)
        encrypted_secret = rsa_encrypt_message(peer_public_key, secret)
        sock.sendall(encrypted_secret)
        log("Sent half-secret")

        encrypted_peer_secret = sock.recv(4096)
        peer_secret = rsa_decrypt_message(rsa_key, encrypted_peer_secret)
        log("Received peer's half-secret")

        common_key = bytes(a ^ b for a, b in zip(secret, peer_secret))
        log("Generated common key")

        block_cipher_communication(sock, common_key)
    except Exception as e:
        log(f"Error in key exchange: {e}")

def block_cipher_communication(sock, common_key):
    try:
        for i in range(2):
            message = f"Message {i+1}"
            iv, ciphertext = encrypt_message(common_key, message.encode())
            sock.sendall(json.dumps({"iv": iv.hex(), "ciphertext": ciphertext.hex()}).encode())
            log(f"Sent: {message}")
            response = sock.recv(4096)
            data = json.loads(response)
            decrypted_message = decrypt_message(common_key, bytes.fromhex(data["iv"]), bytes.fromhex(data["ciphertext"])).decode()
            log(f"Received: {decrypted_message}")
    except Exception as e:
        log(f"Error in block cipher communication: {e}")

def initiate_hello(target_id, target_public_key, rsa_key):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_sock:
            peer_sock.connect(("localhost", target_id))
            log(f"Connected to peer {target_id}")

            hello_message = b"HELLO"
            encrypted_hello = rsa_encrypt_message(target_public_key, hello_message)
            peer_sock.sendall(encrypted_hello)
            log("Sent HELLO")

            encrypted_ack = peer_sock.recv(4096)
            ack_message = rsa_decrypt_message(rsa_key, encrypted_ack)
            log(f"Received: {ack_message.decode()}")

            key_exchange(peer_sock, rsa_key, target_public_key)
    except Exception as e:
        log(f"Error in HELLO exchange: {e}")

def handle_peer_connection(sock, rsa_key, peer_public_key):
    try:
        encrypted_hello = sock.recv(4096)
        hello_message = rsa_decrypt_message(rsa_key, encrypted_hello)
        log(f"Received: {hello_message.decode()}")

        ack_message = b"ACK"
        encrypted_ack = rsa_encrypt_message(peer_public_key, ack_message)
        sock.sendall(encrypted_ack)
        log("Sent ACK")

        key_exchange(sock, rsa_key, peer_public_key)
    except Exception as e:
        log(f"Error handling connection: {e}")

def start_peer_server(client_id, rsa_key):
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("localhost", client_id))
        server_sock.listen(5)
        log(f"P2P server running on port {client_id}")

        while not exit_event.is_set():
            sock, _ = server_sock.accept()
            log("Accepted P2P connection")
            
            target_id = int(input("Enter peer ID for connection: ").strip())
            peer_public_key = get_public_key(target_id)
            if peer_public_key:
                Thread(target=handle_peer_connection, args=(sock, rsa_key, peer_public_key)).start()
            else:
                log("Could not retrieve peer public key.")
                sock.close()
    except Exception as e:
        log(f"Error in P2P server: {e}")

def main():
    if len(sys.argv) < 2:
        log("Usage: python client.py <port>")
        return

    client_id = int(sys.argv[1])
    rsa_key = generate_rsa_key_pair()
    public_key = rsa_key.publickey().export_key()

    register_with_keyserver(client_id, public_key)

    server_thread = Thread(target=start_peer_server, args=(client_id, rsa_key))
    server_thread.start()
    target_id = int(input("Enter peer ID: ").strip())
    target_public_key = get_public_key(target_id)
    if target_public_key is None:
        log("Could not retrieve target's public key. Exiting.")
        return
    if client_id < target_id:
        initiate_hello(target_id, target_public_key, rsa_key)

if __name__ == "__main__":
    main()
