import numpy as np
import sympy as sp

from cipher import Cipher
from math import gcd

def symmetric_alg(text: str, key: tuple, encrypt=True) -> str:
    res = ''
    for letter in text:
        if ord(letter) in range(65, 91):
            value = ord(letter) - 65
            new_ord = 0
            if encrypt:
                new_ord = ((value * key[0] + key[1]) % 26) + 65
            else:
                new_ord = ((key[0] * (value - key[1])) % 26) + 65
            res += chr(new_ord)
        else:
            res += letter
    return res


class AffineCipher(Cipher):
    def __init__(self, cipher_text: None | str = None, plain_text: None | str = None, key: None | tuple = None):
        super().__init__(cipher_text, plain_text, key)
        if gcd(key[0], 26) != 1:
            raise ValueError('Invalid Key')
        self.__dec_key = (sp.mod_inverse(self.key[0], 26), self.key[1])

    def encrypt(self):
        if self.plain_text is None or self.key is None:
            return

        self.cipher_text = symmetric_alg(self.plain_text, self.key)
        return self.cipher_text

    def decrypt(self):
        if self.key is None:
            return

        self.plain_text = symmetric_alg(self.cipher_text, self.__dec_key, False)
        return self.plain_text
