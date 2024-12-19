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
        if padding_len > len(data):  # Fix: Prevent overflows from bad padding
            raise ValueError("Invalid padding length")
        return data[:-padding_len]
    else:
        raise ValueError("Invalid padding type")


class AESProccessor:
    def __init__(self, config):
        self.block_size = config['block_size_bits'] // 8
        self.mode = config['mode']
        self.key = bytes.fromhex(config['key']) if isinstance(config['key'], str) else config['key']
        self.iv = bytes.fromhex(config['iv']) if isinstance(config['iv'], str) else config['iv']
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
            return AES.new(self.key, AES.MODE_CTR, nonce=self.iv[:8])  # Fix: Correct nonce handling
        else:
            raise ValueError("Invalid AES mode")

    def encrypt(self, data):
        data = apply_padding(data, self.block_size, self.padding)
        cipher = self.get_cipher()
        ciphertext = cipher.encrypt(data)
        return cipher.iv if self.iv is None else self.iv, ciphertext  # Fix: Return the generated IV if not provided

    def decrypt(self, data):
        cipher = self.get_cipher()
        decrypted = cipher.decrypt(data)
        return remove_padding(decrypted, self.padding)