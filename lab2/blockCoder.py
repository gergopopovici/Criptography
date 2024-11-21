
from Crypto.Cipher import AES

def apply_padding(data, block_size, padding_type):
    if padding_type == 'zero-padding':
        padding_len = block_size - len(data) % block_size
        return data + b'\x00' * padding_len
    elif padding_type == 'des':
        padding_len = block_size - len(data) % block_size
        return data + b'\x80' + b'\x00' * (padding_len - 1)
    elif padding_type == 'schneier_ferguson':
        padding_len = block_size - len(data) % block_size
        return data + bytes([padding_len] * padding_len)
    else:
        raise ValueError("Invalid padding type")

def remove_padding(data, padding_type):
    if padding_type == 'zero-padding':
        return data.rstrip(b'\x00')
    elif padding_type == 'des':
        return data.rstrip(b'\x00').rstrip(b'\x80')
    elif padding_type == 'schneier_ferguson':
        padding_len = data[-1]
        return data[:-padding_len]
    else:
        raise ValueError("Invalid padding type")
    
class AESProccessor:
    def __init__(self,config):
        self.block_size = config['block_size_bits'] // 8
        self.mode = config['mode']
        self.key = config['key'].encode()
        self.iv = config.get("iv",None)
        if self.iv:
            self.iv = self.iv.encode()
        self.padding = config['padding']
    def get_cipher(self):
        if self.mode == 'ECB':
            return AES.new(self.key, AES.MODE_ECB)
        elif self.mode == 'CBC':
            return AES.new(self.key, AES.MODE_CBC, self.iv)
        elif self.mode == 'CFB':
            return AES.new(self.key, AES.MODE_CFB, self.iv)
        elif self.mode == 'OFB':
            return AES.new(self.key, AES.MODE_OFB, self.iv)
        elif self.mode == 'CTR':
            return AES.new(self.key, AES.MODE_CTR, nonce=self.iv)
        else:
            raise ValueError("Invalid AES mode")
    def encrypt(self, data):
        data = apply_padding(data, self.block_size, self.padding)
        cipher = self.get_cipher()
        return cipher.encrypt(data)
    def decrypt(self, data):
        cipher = self.get_cipher()
        decrypted = cipher.decrypt(data)
        return remove_padding(decrypted, self.padding)
    
def read_gif(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def write_gif(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)

def main():
    config = {
        "block_size_bits": 128,
        "mode": "CBC",
        "key": "1234567890123456",
        "padding": "schneier_ferguson",
        "iv": "1234567890123456"
    }
    aes = AESProccessor(config)
    gif_data = read_gif('./input/input1.gif')
    encrypted = aes.encrypt(gif_data)
    write_gif('./input/encrypted.gif', encrypted)
    decrypted = aes.decrypt(encrypted)
    write_gif('./input/decrypted.gif', decrypted)

if __name__ == "__main__":
    main()
