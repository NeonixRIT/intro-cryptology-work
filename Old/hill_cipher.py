import sympy as sp

from cipher import Cipher
from utils import strip_string, chunk_string


def symmetric_alg(text: str, padding: str, ascii_base: int, key, key_size: int, mod: int) -> str:
    text_no_special = strip_string(text)

    mis = []
    for i in range(0, len(text_no_special) // key_size + 1):
        piece = [ord(char) - ascii_base for char in text_no_special[key_size * i : key_size * (i + 1)]]
        if not piece:
            continue
        if len(piece) < key_size:
            padding = padding * (key_size - len(piece))
            piece += [ord(a) - ascii_base for a in padding]
        mis.append(piece)

    converted_mis = [key * sp.Matrix(mi) % mod for mi in mis]

    res = ''
    for mi in converted_mis:
        for val in mi:
            res += chr(val + ascii_base)

    return res


def create_variable_matrix(key_size: int):
    return sp.Matrix([sp.symbols(' '.join([chr(num) for num in range(65 + val * key_size, 65 + key_size + val * key_size)])) for val in range(key_size)])


class HillCipher(Cipher):
    def __init__(self, cipher_text: None | str = None, plain_text: None | str = None, key: None | tuple = None):
        super().__init__(cipher_text, plain_text, key)
        if key is not None:
            self.key = sp.Matrix(key)
            self.__dec_key = self.key.inv_mod(26)

    def encrypt(self):
        if self.plain_text is None or self.key is None:
            return

        self.cipher_text = symmetric_alg(self.plain_text, 'A', 65, self.key, sp.sqrt(len(self.key)), 26)
        return self.cipher_text

    def decrypt(self):
        if self.key is None:
            return
        if self.plain_text is not None:
            return self.plain_text

        self.plain_text = self.cipher_text = symmetric_alg(self.cipher_text, 'A', 65, self.__dec_key, sp.sqrt(len(self.key)), 26)
        return self.plain_text

    def get_key(self, key_size):
        if self.key is not None:
            return self.key
        if self.cipher_text is None or self.plain_text is None:
            return

        text_no_special = strip_string(self.plain_text)
        cipher_no_special = strip_string(self.cipher_text)

        xis = chunk_string(text_no_special, key_size, True)
        bis = chunk_string(cipher_no_special, key_size, True)

        A = create_variable_matrix(key_size)  # Create square matrix of variables for the key

        # Use A to create systems of equations for each letter in plain/cipher text
        eq_sets = [list(sp.Matrix([A * sp.Matrix(x) for x in xis]))[i::key_size] for i in range(key_size)]

        # Make equations equal 0
        for i, eq_set in enumerate(eq_sets):
            for j, eq in enumerate(eq_set):
                eq_set[j] = eq + (bis[j][i] * -1)

        # Solve the systems of equations
        vals = []
        eq_set: list[sp.Expr]
        for eq_set in eq_sets:
            row = []
            for num in list(sp.solve(eq_set[:key_size], set=True)[1])[0]:
                # Undo last step of the solve to get the key values
                top = (num.numerator) % 26
                bot = sp.mod_inverse((num.denominator) % 26, 26)
                res = (bot * top) % 26
                row.append(res)
            vals.append(tuple(row))
        return tuple(vals)
