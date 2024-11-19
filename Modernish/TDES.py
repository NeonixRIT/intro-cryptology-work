"""
TDES, Encrypt: ENC_k1 -> DEC_k2 -> ENC_k3
TDES, Decrypt: DEC_k3 -> ENC_k2 -> DEC_k1

SUPPORTS 3 Key Options:
    1. Key 1, 2, 3 are independent (192 bit key, 168 used, ~112 security)
    2. Key 1, 2 are independent, Key 3 = Key 1 (128 bit key, 112 used, ~? security)
    3. Key 1 = Key 2 = Key 3 (64 bit key, 56 used, ~56 security), functionally same as DES
"""

from DES import DES


class TDES:
    def __init__(self, key_mode: int = 1):
        self.key_mode = key_mode
        self.key_size = 24 if key_mode == 1 else 16 if key_mode == 2 else 8
        self.des_1 = DES()
        self.des_2 = DES()
        self.des_3 = DES()
        self.block_size = 64

    def encrypt_block(self, data: bytes, key: bytes) -> bytes:
        if len(key) != self.key_size:
            raise ValueError(f'Invalid key size: {len(key) * 8}. Expected {self.key_size * 8}.')
        if self.key_mode == 1:
            k1, k2, k3 = key[:8], key[8:16], key[16:]
        elif self.key_mode == 2:
            k1, k2, k3 = key[:8], key[8:16], key[:8]
        else:
            k1, k2, k3 = key, key, key
        return self.des_1.encrypt_block(self.des_2.decrypt_block(self.des_3.encrypt_block(data, k3), k2), k1)

    def decrypt_block(self, data: bytes, key: bytes) -> bytes:
        if len(key) != self.key_size:
            raise ValueError(f'Invalid key size: {len(key) * 8}. Expected {self.key_size * 8}.')
        if self.key_mode == 1:
            k1, k2, k3 = key[:8], key[8:16], key[16:]
        elif self.key_mode == 2:
            k1, k2, k3 = key[:8], key[8:16], key[:8]
        else:
            k1, k2, k3 = key, key, key
        return self.des_3.decrypt_block(self.des_2.encrypt_block(self.des_1.decrypt_block(data, k1), k2), k3)


def main():
    plaintext = b'\x11\x22\x33\x44\x55\x66\x77\x88'
    key = b'0123456789abcdefghijklmo'
    expected_ciphertext = b'\x2c\xd1\x3a\xea\xbd\xbc\x60\xc6'
    cipher = TDES()

    print('Plaintext  (inp) :'.ljust(20), plaintext.hex().upper())
    print('Key        (inp) :'.ljust(20), key.hex().upper())
    print()
    print('Ciphertext (exp) :'.ljust(20), expected_ciphertext.hex().upper())
    actual_ciphertext = cipher.encrypt_block(plaintext, key)
    print('Ciphertext (act) :'.ljust(20), actual_ciphertext.hex().upper())
    print('Plaintext  (exp) :'.ljust(20), plaintext.hex().upper())
    print('Plaintext  (act) :'.ljust(20), cipher.decrypt_block(actual_ciphertext, key).hex().upper())


if __name__ == '__main__':
    main()
