import numpy as np

from os import urandom
from sys import byteorder

from key import Key
from stream_cipher import StreamCipher, StreamGenerator


class BBSKey(Key):
    def __init__(self, n: int = None, seed: list[int] | str | int = None):
        if isinstance(seed, str):
            seed = int(seed, 2)
        elif isinstance(seed, list):
            seed = int(''.join([str(bit) for bit in seed]), 2)

        self.n = int.from_bytes(urandom(np.random.randint(4, 128)), byteorder=byteorder) if n is None else n
        self.seed = int.from_bytes(urandom(np.random.randint(4, 128)), byteorder=byteorder) if seed is None else seed

        friendly_name = f'n={hex(n)}, seed={seed}'
        super().__init__(seed, friendly_name)


def bbs_ksg(key: BBSKey, length=1000):
    n = key.n
    xi = key.seed
    for _ in range(length):
        xi = (xi**2) % n
        yield xi % 2


class BBSKSG(StreamGenerator):
    def __init__(self, key):
        super().__init__(key)

    def __call__(self, length):
        return bbs_ksg(self.key, length)


class BBSCipher(StreamCipher):
    def __init__(self, plain_text: str = None, cipher_text: str = None, key: BBSKey = None):
        key = BBSKey() if key is None else key
        super().__init__(plain_text, cipher_text, BBSKSG(key))
