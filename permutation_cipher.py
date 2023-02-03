from cipher import Cipher
from utils import strip_string


def pad_string(text: str, pad_char: str, key: dict) -> str:
    padding = ''
    if len(text) % len(key) > 0:
        padding = pad_char * (len(key) - (len(text) % len(key)))
    return text + padding


def symmetric_alg(text: str, key: dict) -> str:
    res = ''
    for i in range(0, len(text) // len(key) + 1):
        piece = text[len(key) * i:len(key) * (i + 1)]
        for j, _ in enumerate(piece):
            res += piece[key[j + 1] - 1]
    return res


class PermCipher(Cipher):
    def __init__(self, cipher_text: None | str = None, plain_text: None | str = None, key: None | dict = None):
        super().__init__(cipher_text, plain_text, key)
        self.__dec_key = {v: k for k, v in self.key.items()} if self.key is not None else None

    def encrypt(self):
        if self.plain_text is None:
            return

        if self.key is None:
            self.key = self.generate_key()

        text_no_special = strip_string(self.plain_text)
        text_no_special = pad_string(text_no_special, 'A', self.key)

        self.cipher_text = symmetric_alg(text_no_special, self.key)
        return self.cipher_text

    def decrypt(self):
        if self.cipher_text is None:
            return

        if self.key is None:
            self.key = self.generate_key()

        text_no_special = strip_string(self.cipher_text)
        text_no_special = pad_string(text_no_special, 'A', self.key)

        self.plain_text = symmetric_alg(text_no_special, self.__dec_key)
        return self.plain_text
