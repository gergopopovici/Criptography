import socket
import json
import sys
from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from blockCoder import AESProccessor

KEY_SERVER_HOST = 'localhost'
KEY_SERVER_PORT = 8000
HARDCODED_IV = b'0123456789abcdef'

exit_flag = False

def log(message):
    print(f"[LOG] {message}")

def register_with_keyserver(client_id, public_key):
    log(f"Registering with KeyServer as {client_id}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((KEY_SERVER_HOST, KEY_SERVER_PORT))
        request = {
            "action": "register",
            "client_id": client_id,
            "public_key": public_key.decode()
        }
        sock.sendall(json.dumps(request).encode())
        response = sock.recv(1024)
        log(f"KeyServer response: {response.decode()}")

def get_public_key(client_id, target_id):
    log(f"Requesting public key for {target_id}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((KEY_SERVER_HOST, KEY_SERVER_PORT))
        request = {"action": "get_key", "client_id": client_id, "target_id": target_id}
        sock.sendall(json.dumps(request).encode())
        response = sock.recv(4096)
        
        if not response:
            log("KeyServer returned an empty response.")
            return None
        
        try:
            response_data = json.loads(response.decode())
            return response_data.get("public_key")
        except json.JSONDecodeError:
            log(f"Error decoding KeyServer response: {response.decode()}")
            return None

def generate_shared_key(rsa_key, recipient_public_key):
    recipient_key = RSA.import_key(recipient_public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    shared_key = HARDCODED_IV  # Use hardcoded IV as the shared key
    encrypted_key = cipher_rsa.encrypt(shared_key)
    return shared_key, encrypted_key

def decrypt_shared_key(rsa_key, encrypted_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    shared_key = cipher_rsa.decrypt(encrypted_key)
    return shared_key

def handle_peer_connection(peer_sock, rsa_key, client_id):
    try:
        encrypted_key = peer_sock.recv(4096)
        shared_key = decrypt_shared_key(rsa_key, encrypted_key)
        log(f"[{client_id}] Decrypted shared key from peer.")

        aes_processor = AESProccessor({
            'block_size_bits': 128,
            'mode': 'CBC',
            'key': shared_key.hex(),
            'iv': HARDCODED_IV.hex(),
            'padding': 'schneier_ferguson'
        })

        for i in range(2):
            response = peer_sock.recv(4096)
            if not response:
                log(f"[{client_id}] Empty message from peer.")
                break

            data = json.loads(response.decode())
            ciphertext = bytes.fromhex(data["ciphertext"])
            decrypted_message = aes_processor.decrypt(ciphertext).decode()
            log(f"[{client_id}] Received: {decrypted_message}")

            message = f"Message {i + 1} from client {client_id}"
            iv, ciphertext = aes_processor.encrypt(message.encode())
            peer_sock.sendall(json.dumps({"iv": iv.hex(), "ciphertext": ciphertext.hex()}).encode())
            log(f"[{client_id}] Sent: {message}")
    except Exception as e:
        log(f"[{client_id}] Error handling peer connection: {e}")
    finally:
        log(f"[{client_id}] P2P connection closed.")
        peer_sock.close()

def start_peer_server(client_id, rsa_key):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(('localhost', client_id))
    server_sock.listen(5)
    log(f"P2P server running on port {client_id}")

    while not exit_flag:
        try:
            server_sock.settimeout(1.0)  # Allow periodic checks for exit_flag
            peer_sock, addr = server_sock.accept()
            log(f"Accepted P2P connection from {addr}")
            Thread(target=handle_peer_connection, args=(peer_sock, rsa_key, client_id)).start()
        except socket.timeout:
            continue  # Retry if timeout occurs

    server_sock.close()
    log("P2P server stopped.")

def main():
    global exit_flag  # Use the global flag to signal the server thread to exit

    if len(sys.argv) < 2:
        log("Usage: python client.py <port>")
        return
    client_id = int(sys.argv[1])

    rsa_key = RSA.generate(2048)
    public_key = rsa_key.publickey().export_key()

    log(f"Client running with ID {client_id}")

    register_with_keyserver(client_id, public_key)

    server_thread = Thread(target=start_peer_server, args=(client_id, rsa_key))
    server_thread.start()

    while True:
        command = input("Enter command (register/getkey/exit/p2p <target_id>): ").strip().lower()

        if command == "register":
            register_with_keyserver(client_id, public_key)
        elif command.startswith("getkey"):
            try:
                target_id = int(command.split()[1])
                key = get_public_key(client_id, target_id)
                if key:
                    log(f"Retrieved public key for {target_id}: {key}")
                else:
                    log(f"Public key for {target_id} not found.")
            except (IndexError, ValueError):
                log("Usage: getkey <target_id>")
        elif command.startswith("p2p"):
            try:
                target_id = int(command.split()[1])

                peer_public_key = get_public_key(client_id, target_id)
                if not peer_public_key:
                    log(f"Public key for client {target_id} not found.")
                    continue

                shared_key, encrypted_key = generate_shared_key(rsa_key, peer_public_key)
                log(f"Generated and encrypted shared key for client {target_id}")

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_sock:
                    peer_sock.connect(("localhost", target_id))
                    log(f"Connected to peer {target_id}")

                    log("Sending encrypted shared key...")
                    peer_sock.sendall(encrypted_key)

                    aes_processor = AESProccessor({
                        'block_size_bits': 128,
                        'mode': 'CBC',
                        'key': shared_key.hex(),
                        'iv': HARDCODED_IV.hex(),
                        'padding': 'schneier_ferguson'
                    })

                    for i in range(2):
                        message = f"Message {i + 1} from client {client_id}"
                        iv, ciphertext = aes_processor.encrypt(message.encode())
                        peer_sock.sendall(json.dumps({"iv": iv.hex(), "ciphertext": ciphertext.hex()}).encode())
                        log(f"Sent: {message}")

                        response = peer_sock.recv(4096)
                        if not response:
                            log("Empty response from peer.")
                            break
                        data = json.loads(response.decode())
                        ciphertext = bytes.fromhex(data["ciphertext"])
                        decrypted_message = aes_processor.decrypt(ciphertext).decode()
                        log(f"Received: {decrypted_message}")
            except Exception as e:
                log(f"Error during P2P communication: {e}")
            finally:
                log("P2P connection closed.")

        elif command == "exit":
            log("Exiting...")
            exit_flag = True
            server_thread.join() 
            log("Goodbye!")
            break
        else:
            log("Unknown command. Available commands: register, getkey <target_id>, p2p <target_id>, exit")

if __name__ == "__main__":
    main()