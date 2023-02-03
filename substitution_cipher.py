from cipher import Cipher


def symmetric_alg(text: str, key: dict) -> str:
    res = ''
    for letter in text:
        if letter in key:
            res += key[letter]
        else:
            res += letter
    return res


class SubCipher(Cipher):
    def __init__(self, cipher_text: None | str = None, plain_text: None | str = None, key: None | dict = None):
        super().__init__(cipher_text, plain_text, key)
        self.__dec_key = {v: k for k, v in self.key.items()} if self.key is not None else None

    def encrypt(self):
        if self.plain_text is None or self.key is None:
            return

        self.cipher_text = symmetric_alg(self.plain_text, self.key)
        return self.cipher_text

    def decrypt(self):
        if self.key is None:
            return

        self.plain_text = symmetric_alg(self.cipher_text, self.__dec_key)
        return self.plain_text
