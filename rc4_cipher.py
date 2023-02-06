import numpy as np

from os import urandom
from sys import byteorder

from key import Key
from stream_cipher import StreamCipher, StreamGenerator
from utils import string_to_bytes


class RC4Key(Key):
    def __init__(self, seed: str | list = None, is_string: bool = False, is_binary: bool = False):
        self.is_string = is_string
        self.is_binary = is_binary

        friendly_name = None
        if seed is None:
            size = np.random.randint(64 // 8, 2048 // 8)
            seed = [int.from_bytes(urandom(1), byteorder=byteorder) for _ in range(size)]

        if is_string:
            friendly_name = seed
            seed = string_to_bytes(seed)
        elif is_binary:
            tmp_key_val = ' '.join([hex(byte) for byte in seed])
            friendly_name = tmp_key_val

        self.seed = seed

        super().__init__(seed, friendly_name)


def rc4_ksg(key, length=1000):
    if len(key.seed) < 1 or len(key.seed) > 2048:
        raise ValueError(f'Key length must be between 1 and 2048 bits: {len(key.seed)}')

    s = list(range(256))

    j = 0
    for i in range(256):
        j = (j + s[i] + key.seed[i % len(key.seed)]) % 256
        s[i], s[j] = s[j], s[i]

    i = 0
    j = 0
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        for bit in bin(k)[2:].zfill(8):
            yield int(bit)


class RC4KSG(StreamGenerator):
    def __init__(self, key):
        super().__init__(key)

    def __call__(self, length):
        return rc4_ksg(self.key, length)


class RC4(StreamCipher):
    def __init__(self, plain_text: str = None, cipher_text: str = None, key: RC4Key = None):
        key = RC4Key(is_binary=True) if key is None else key
        super().__init__(plain_text, cipher_text, RC4KSG(key))
