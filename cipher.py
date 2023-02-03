class Cipher:
    __slots__ = ['cipher_text', 'plain_text', 'key']

    def __init__(self, cipher_text: None | str = None, plain_text: None | str = None, key: None | str | int | dict = None):
        self.cipher_text = cipher_text
        self.plain_text = plain_text
        self.key = key

    def encrypt(self):
        raise NotImplementedError()

    def decrypt(self):
        raise NotImplementedError()

    def get_key(self, **kwargs):
        raise NotImplementedError()

    def generate_key(self, **kwargs):
        raise NotImplementedError()
