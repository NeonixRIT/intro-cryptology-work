class Arcfour:
    def __init__(self) -> None:
        pass

    def ksg(self, key: bytes):
        s = list(range(256))

        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) % 256
            s[i], s[j] = s[j], s[i]

        i = 0
        j = 0
        while True:
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            s[i], s[j] = s[j], s[i]
            k = s[(s[i] + s[j]) % 256]
            yield k

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        ks = self.ksg(key)
        return b''.join(bytes([next(ks) ^ byte]) for byte in data)

    def decrypt(self, data: bytes, key: bytes) -> bytes:
        ks = self.ksg(key)
        return b''.join(bytes([next(ks) ^ byte]) for byte in data)


ARC4 = Arcfour()
