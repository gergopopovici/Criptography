class VigenereProcessor:
    def __init__(self, config):
        self.key = config['key'].encode()
        self.mode = config['mode']
        self.iv = config.get("iv", None)
        if self.iv:
            self.iv = self.iv.encode()
        self.padding = config['padding']

    def _extend_key(self, data):
        key_length = len(self.key)
        data_length = len(data)
        
        repeated_key = self.key * (data_length // key_length)
        remaining_key = self.key[:data_length % key_length]
        extended_key = repeated_key + remaining_key
        
        return extended_key

    def _xor_bytes(self, data, key):
        return bytes([x ^ y for x, y in zip(data, key)])

    def apply_padding(self, data, block_size):
        if self.padding == 'zero-padding':
            padding_len = block_size - len(data) % block_size
            return data + b'\x00' * padding_len
        elif self.padding == 'des':
            padding_len = block_size - len(data) % block_size
            return data + b'\x80' + b'\x00' * (padding_len - 1)
        elif self.padding == 'schneier_ferguson':
            padding_len = block_size - len(data) % block_size
            return data + bytes([padding_len] * padding_len)
        else:
            raise ValueError("Invalid padding type")

    def remove_padding(self, data):
        if self.padding == 'zero-padding':
            return data.rstrip(b'\x00')
        elif self.padding == 'des':
            return data.rstrip(b'\x00').rstrip(b'\x80')
        elif self.padding == 'schneier_ferguson':
            padding_len = data[-1]
            return data[:-padding_len]
        else:
            raise ValueError("Invalid padding type")

    def encrypt(self, data):
        block_size = len(self.key)
        data = self.apply_padding(data, block_size)
        encrypted = b""
        if self.mode == "ECB":
            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                encrypted += self._xor_bytes(block, self.key)
        elif self.mode == "CBC":
            previous_block = self.iv
            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                block = self._xor_bytes(block, previous_block)
                encrypted_block = self._encrypt_block(block)
                encrypted += encrypted_block
                previous_block = encrypted_block
        elif self.mode == "CFB":
            previous_block = self.iv
            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                encrypted_block = self._encrypt_block(previous_block)
                xor_block = self._xor_bytes(block, encrypted_block)
                encrypted += xor_block
                previous_block = xor_block
        elif self.mode == "OFB":
            previous_block = self.iv
            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                previous_block = self._encrypt_block(previous_block)
                encrypted_block = self._xor_bytes(block, previous_block)
                encrypted += encrypted_block
        elif self.mode == "CTR":
            counter = int.from_bytes(self.iv, 'big')
            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                counter_block = counter.to_bytes(block_size, 'big')
                encrypted_counter = self._encrypt_block(counter_block)
                xor_block = self._xor_bytes(block, encrypted_counter)
                encrypted += xor_block
                counter += 1
        else:
            raise ValueError("Invalid mode")
        return encrypted

    def decrypt(self, data):
        block_size = len(self.key)
        decrypted = b""
        if self.mode == "ECB":
            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                decrypted += self._xor_bytes(block, self.key)
        elif self.mode == "CBC":
            previous_block = self.iv
            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                decrypted_block = self._decrypt_block(block)
                decrypted_block = self._xor_bytes(decrypted_block, previous_block)
                decrypted += decrypted_block
                previous_block = block
        elif self.mode == "CFB":
            previous_block = self.iv
            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                encrypted_block = self._encrypt_block(previous_block)
                xor_block = self._xor_bytes(block, encrypted_block)
                decrypted += xor_block
                previous_block = block
        elif self.mode == "OFB":
            previous_block = self.iv
            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                previous_block = self._encrypt_block(previous_block)
                decrypted_block = self._xor_bytes(block, previous_block)
                decrypted += decrypted_block
        elif self.mode == "CTR":
            counter = int.from_bytes(self.iv, 'big')
            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                counter_block = counter.to_bytes(block_size, 'big')
                encrypted_counter = self._encrypt_block(counter_block)
                xor_block = self._xor_bytes(block, encrypted_counter)
                decrypted += xor_block
                counter += 1
        else:
            raise ValueError("Invalid mode")
        return self.remove_padding(decrypted)

    def _encrypt_block(self, block):
        extended_key = self._extend_key(block)
        encrypted_block = [(b + k) % 256 for b, k in zip(block, extended_key)]
        return bytes(encrypted_block)

    def _decrypt_block(self, block):
        extended_key = self._extend_key(block)
        decrypted_block = [(b - k) % 256 for b, k in zip(block, extended_key)]
        return bytes(decrypted_block)