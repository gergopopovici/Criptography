import socket
import json

host = 'localhost'
port = 8000

TEST_PUBLIC_KEY = """MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3HMvoCkgIcMGPbZ8prl/
Sir7JLFvqof9U0gitS2+9VYJizcon3uMwEFcDobpLj4hiL2nxKpcTvSayt37tDUc
Cxq9DEnUH8UXlmw/M+RE5s8L3cck/sRCEW4eH0kXpGbFh/F+tlNHdEboC61PzleS
BG8tAOdEHxNAEtOZqMihSEjCOESckpH2S+i67wnmS1qPg6tpfJR6uIrYdcEmwKxo
1ZlbYZavs9SnRIr38a2sjCt4vgafKRWerenOw4W+zHzI7IKm31Dxnzt2GcJrYRKn
hMdP2qCtVtU4ZO/h7aUCV1I9Yz8OEbqANX6ZYVYHEFFpItfz8v24p/I5IUXIQZkt
jQIDAQAB
-----END PUBLIC KEY-----"""

try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    print(f'[test_client]: Connected to server at {host}:{port}')

    register_request = {
        "action": "register",
        "client_id": port,
        "public_key": TEST_PUBLIC_KEY
    }
    client.sendall(json.dumps(register_request).encode('utf-8'))

    response = client.recv(4096)
    print(f'[test_client]: Server response to registerPubKey: {response.decode("utf-8")}')

except Exception as e:
    print(f'[test_client]: An error occurred: {e}')
finally:
    print('[test_client]: Disconnecting from server...')
    client.close()