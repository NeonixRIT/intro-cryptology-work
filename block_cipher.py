from key import Key
from utils import chunk_string, string_to_bits, bits_to_bytes


class KeyStreamGenerator:
    def __init__(self, key):
        self.key = key

    def __call__(self, encrypt: bool):
        raise NotImplementedError()


class BlockCipher:
    def __init__(self, plaintext: str, ciphertext: str, block_size: int, ksa: KeyStreamGenerator, block_function):
        self.plaintext = plaintext
        self.ciphertext = ciphertext
        self.block_size = block_size
        self.ksa = ksa
        self.key = self.ksa.key
        self.block_function = block_function

    def encrypt(self):
        plain_blocks = [''.join([str(i) for i in chunk]).ljust(self.block_size, '0') for chunk in chunk_string(string_to_bits(self.plaintext), self.block_size)]

        res = ''
        for block in plain_blocks:
            ksa = self.ksa(encrypt=True)
            res += self.block_function(block, ksa)
        self.ciphertext = res
        return self.ciphertext


    def decrypt(self, character_size: int = 8):
        cipher_blocks = [''.join([str(i) for i in chunk]).ljust(self.block_size, '0') for chunk in chunk_string(self.ciphertext, self.block_size)]

        binary = ''
        for block in cipher_blocks:
            ksa = self.ksa(encrypt=False)
            binary += ''.join(self.block_function(block, ksa))

        bin_letters = chunk_string(binary, character_size)

        res = ''
        for bin_letter in bin_letters:
            res += chr(int(bin_letter, 2))

        self.plaintext = res
        return self.plaintext
