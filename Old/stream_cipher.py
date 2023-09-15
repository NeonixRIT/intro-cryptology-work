from utils import chunk_string


class StreamGenerator:
    def __init__(self, key):
        self.key = key

    def __call__(self, length):
        raise NotImplementedError()


def symmetric_alg(binary: str | list[str | int], ksg):
    new_binary = ''
    for bit in binary:
        new_bit = int(bit) ^ next(ksg)
        new_binary += str(new_bit)
    return new_binary


class StreamCipher:
    def __init__(self, plain_text, cipher_text, stream_gen: StreamGenerator):
        self.plain_text = plain_text
        self.cipher_text = cipher_text
        self.key = stream_gen.key
        self.__stream_gen = stream_gen

    def encrypt(self):
        if self.plain_text is None:
            return
        binary = ''.join([bin(ord(char))[2:].zfill(8) for char in self.plain_text])
        length = len(binary) + 1
        ksg = self.__stream_gen(length)
        self.cipher_text = symmetric_alg(binary, ksg)
        return self.cipher_text

    def decrypt(self, base: int = 8):
        if self.cipher_text is None:
            return
        length = len(self.cipher_text) + 1
        ksg = self.__stream_gen(length)

        binary = symmetric_alg(self.cipher_text, ksg)
        bin_letters = chunk_string(binary, base)

        res = ''
        for bin_letter in bin_letters:
            res += chr(int(bin_letter, 2))

        self.plain_text = res
        return self.plain_text
