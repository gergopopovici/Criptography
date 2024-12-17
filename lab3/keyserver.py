import socket
import threading
import json

KEY_SERVER_HOST = 'localhost'
KEY_SERVER_PORT = 8000

client_keys = {}

def log(message):
    print(f"[LOG] {message}")

def handle_client(client_socket, addr):
    log(f"Connection from {addr}")
    try:
        data = client_socket.recv(4096)
        if not data:
            log("No data received, closing connection.")
            return

        request = json.loads(data.decode())
        action = request.get('action')
        client_id = request.get('client_id')

        if action == "register":
            public_key = request.get('public_key')
            if client_id and public_key:
                client_keys[client_id] = public_key
                log(f"Client {client_id} registered with public key.")
                client_socket.sendall(b"OK")
            else:
                log("Missing client_id or public_key in register request.")
                client_socket.sendall(b"ERROR: Missing client_id or public_key")
        
        elif action == "get_key":
            target_id = request.get('target_id')
            if target_id in client_keys:
                response = {"public_key": client_keys[target_id]}
                client_socket.sendall(json.dumps(response).encode())
                log(f"Sent public key of {target_id} to {client_id}.")
            else:
                log(f"Client {target_id} not found.")
                client_socket.sendall(b"ERROR: Target client not found")
        
        else:
            log("Invalid action received.")
            client_socket.sendall(b"ERROR: Invalid action")
    
    except Exception as e:
        log(f"Error: {e}")
        client_socket.sendall(f"ERROR: {str(e)}".encode())
    finally:
        client_socket.close()
        log(f"Connection with {addr} closed.")

def main():
    log("Starting KeyServer...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((KEY_SERVER_HOST, KEY_SERVER_PORT))
    server_socket.listen(5)
    log(f"KeyServer running on {KEY_SERVER_HOST}:{KEY_SERVER_PORT}")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
            client_thread.start()
    except KeyboardInterrupt:
        log("KeyServer shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
