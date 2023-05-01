from cipher import Cipher
from utils import bool_prompt, EN_DICTIONARY, wrap


class ShiftCipher(Cipher):
    def __init__(self, cipher_text: None | str = None, plain_text: None | str = None, key: None | int = None):
        super().__init__(cipher_text, plain_text, key)

    def encrypt(self):
        if self.plain_text is None or self.key is None:
            return
        self.cipher_text = ''.join([chr(ascii_num) for ascii_num in [wrap(ord(char), self.key) for char in list(self.plain_text)]])
        return self.cipher_text

    def decrypt(self):
        if self.key is None:
            return
        if self.plain_text is not None:
            return self.plain_text
        self.plain_text = ''.join([chr(ascii_num) for ascii_num in [wrap(ord(char), -1 * self.key) for char in list(self.cipher_text)]])
        return self.plain_text

    def get_key(self):
        chars = {chr(num).upper() for num in range(65, 91)}
        if self.key is not None:
            return self.key
        if self.cipher_text is None:
            return

        perms = {}
        for shift in range(1, 26):
            permutation = ''
            for letter in list(self.cipher_text):
                if letter in chars:
                    permutation += chr(wrap(ord(letter), -1 * shift))
                else:
                    permutation += letter
            perms[shift] = permutation

        # Try solve using english dictionary
        for key, perm in perms.items():
            words = perm.split(' ')
            res = {1 if word in EN_DICTIONARY else 0 for word in words}
            if len(res & {1}) == 1:
                self.key = key
                self.plain_text = perm
                return key, perm

        # Show every permutation and have solution manually verified
        for key, perm in perms.items():
            print(f'KEY: {key}\nPLAINTEXT: {perm}')
            is_solved = bool_prompt('Is this the solution?', False)
            if is_solved:
                self.key = key
                self.plain_text = perm
                return key, perm
        return
