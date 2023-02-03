import numpy as np

from stream_cipher import StreamCipher, StreamGenerator


def rc4_ksg(key, length=1000):
    if len(key) < 40 or len(key) > 2048:
        raise ValueError('Key length must be between 40 and 2048 bits')

    s = list(range(256))

    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
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
    def __init__(self, seed):
        super().__init__(seed)

    def __call__(self, length):
        return rc4_ksg(self.seed, length)


class RC4(StreamCipher):
    def __init__(self, plain_text: str = None, cipher_text: str = None, key: str | list = None):
        key = [np.random.randint(i, (i + 1) ** 3) % 2 for i in range(np.random.randint(40, 2049))] if key is None else key
        super().__init__(plain_text, cipher_text, RC4KSG(key))
