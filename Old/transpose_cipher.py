import numpy as np

from cipher import Cipher
from utils import strip_string, chunk_string


def pad_string(text: str, pad_char: str, key: int):
    padding = ''
    if len(text) > (key**2):
        len_padding = (len(text) % key + 1) * (key**2) - len(text)
        padding = pad_char * len_padding
    else:
        len_padding = (key**2) - len(text)
        padding = pad_char * len_padding
    return text + padding


def symmetric_alg(text: str, key: int) -> str:
    matrix = chunk_string(text, key, convert_ascii=True, ascii_base=0)
    matricies = [matrix[key * i : key * (i + 1)] for i in range(len(matrix) // key)]
    trans_matricies = [np.transpose(np.array(matrix)) for matrix in matricies]

    return ''.join(list([chr(num) for matrix in trans_matricies for row in matrix for num in row]))


class TransCipher(Cipher):
    def __init__(self, cipher_text: None | str = None, plain_text: None | str = None, key: None | int = None):
        super().__init__(cipher_text, plain_text, key)

    def encrypt(self):
        if self.plain_text is None or self.key is None:
            return

        text_no_special = strip_string(self.plain_text)
        text_no_special = pad_string(text_no_special, 'A', self.key)

        self.cipher_text = symmetric_alg(text_no_special, self.key)

        return self.cipher_text

    def decrypt(self):
        if self.cipher_text is None or self.key is None:
            return

        text_no_special = strip_string(self.cipher_text)
        text_no_special = pad_string(text_no_special, 'A', self.key)

        self.plain_text = symmetric_alg(text_no_special, self.key)

        return self.plain_text
