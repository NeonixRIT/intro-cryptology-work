MIX_MATRIX = [[0x02, 0x03, 0x01, 0x01], [0x01, 0x02, 0x03, 0x01], [0x01, 0x01, 0x02, 0x03], [0x03, 0x01, 0x01, 0x02]]

MIX_MATRIX_INV = [[0x0E, 0x0B, 0x0D, 0x09], [0x09, 0x0E, 0x0B, 0x0D], [0x0D, 0x09, 0x0E, 0x0B], [0x0B, 0x0D, 0x09, 0x0E]]

S_BOX = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16],
]

S_BOX_INV = [
    [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D],
]

ROUND_CONSTANTS = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# IR_POLY = 0x11B


def xor_words(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a) ^ int.from_bytes(b)).to_bytes(4, 'big')


def words_to_bytes(words: list[bytes]) -> bytes:
    return b''.join(words)


def GF_256_multiply(a: int, b: int) -> int:
    """
    Handles multiplication in GF(2^8)

    So with polynomials a, b represented as bits
    each loop iteration, consumes the rightmost bit of b
    if that bit is 1, we xor a with the result
    then we shift a one bit to the left
    if a's leftmost bit was 1, we xor a with 0x1b
    then we shift b one bit to the right
    the result should be 8 bits long so we mod 256
    """
    p = 0
    for _ in range(8):
        if b & 1:  # Rightmost bit of b is set
            p ^= a  # Exclusive OR (polynomial addition)
        carry = a & 0x80  # Leftmost bit of a
        a <<= 1  # Shift a one bit to the left
        if carry:  # If carry had a value of one
            a ^= 0x1B  # Exclusive OR with 0x1b
        b >>= 1  # Shift b one bit to the right
    return p & 0xFF


class State:
    def __init__(self, data: bytes):
        self.__columns = [list(data[i : i + 4]) for i in range(0, len(data), 4)]

    def __str__(self) -> str:
        return '\n'.join([str([f'0x{hex(self.__columns[i][j])[2:].zfill(2).upper()}' for i in range(4)])[1:-1] for j in range(4)]).replace("'", '').replace(',', '')

    def __repr__(self) -> str:
        return self.__str__()

    def __getitem__(self, index: int) -> list[int]:
        return self.__columns[index]

    def __setitem__(self, index: int, value: list[int]):
        self.__columns[index] = value

    def __iter__(self):
        return iter(self.__columns)

    def __len__(self) -> int:
        return len(self.__columns)

    def __calc_idx_norm(self, i, j):
        return (i + j) % 4

    def __calc_idx_inv(self, i, j):
        return (i - j) % 4

    def shift_rows(self, inverse: bool = False):
        result = [[0] * len(self[0]) for _ in range(len(self))]
        calc_idx_func = self.__calc_idx_inv if inverse else self.__calc_idx_norm
        for i in range(4):
            for j in range(4):
                new_i = calc_idx_func(i, j)
                result[new_i][j] = self[i][j]
        self.__columns = result

    def xor(self, other) -> None:
        for i in range(4):
            for j in range(4):
                self[i][j] ^= other[i][j]

    def mix_columns(self, inverse: bool = False):
        matrix = MIX_MATRIX_INV if inverse else MIX_MATRIX
        result = [[0] * len(self[0]) for _ in range(len(matrix))]
        for i in range(len(matrix)):
            for j in range(len(self[0])):
                for k in range(len(self)):
                    result[j][i] ^= GF_256_multiply(matrix[i][k], self[j][k])
        self.__columns = result

    def to_bytes(self) -> bytes:
        return words_to_bytes([bytes(val) for val in self.__columns])


class AES:
    def __init__(self, Nk: int, Nr: int):
        self.block_size = 128
        self.key_size = Nk * 32
        self.Nr = Nr
        self.Nk = Nk

    def _byte_substitution(self, state: list[bytes] | bytes, inverse: bool = False) -> bytes:
        s_box = S_BOX_INV if inverse else S_BOX
        poly_bytes = [b for row in state for b in row] if isinstance(state[0], list) else [s for s in state]
        for i, byte in enumerate(poly_bytes):
            row = (byte & 0xF0) >> 4
            col = byte & 0x0F
            poly_bytes[i] = s_box[row][col]
        return bytes(poly_bytes)

    def _g(self, word: bytes, rc_i: int) -> bytes:
        shifted = word[1:] + word[:1]
        subbed = list(self._byte_substitution(shifted))
        xor_rc = subbed[0] ^ rc_i
        rcond = bytes([xor_rc] + subbed[1:])
        return bytes(rcond)

    def _ksa(self, key: bytes):
        rc = ROUND_CONSTANTS
        # Split key bytes into appropriate number of words for key length
        if len(key) * 8 != self.key_size:
            raise ValueError(f'Invalid key length {len(key) * 8}. Expected {self.key_size}.')
        words = [key[i : i + 4] for i in range(0, len(key), 4)]

        # Return 128 bit round keys of initial key until 128 bits of initial key are not left
        i = 0
        while len(words) - i >= 4:
            yield words_to_bytes(words[i : i + 4])
            i += 4

        # Generate round keys, 1 word at a time, yeilding last 4 words every 4 words generated
        temp = words[-1]
        for i in range(self.Nk, self.Nr * 4 + 4):
            temp = words[-1]
            if i % self.Nk == 0:
                temp = self._g(temp, rc[(i // self.Nk) - 1])
            elif len(words) % 4 == 0 and self.key_size == 256:
                temp = self._byte_substitution(temp)
            temp = xor_words(words[i - self.Nk], temp)
            words.append(temp)
            if (i + 1) % 4 == 0:
                yield words_to_bytes(words[-4:])

    def encrypt_block(self, block: bytes, key: bytes) -> bytes:
        keys = [State(round_key) for round_key in self._ksa(key)]
        state = State(block)

        # First Round
        state.xor(keys[0])

        # Rest of The Rounds Except Last
        for i in range(1, self.Nr):
            state = State(self._byte_substitution(state))  # Substitute Bytes
            state.shift_rows()   # Shift Rows
            state.mix_columns()  # Mix Columns
            state.xor(keys[i])   # Add Round Key

        # Last Round
        state = State(self._byte_substitution(state))  # Substitute Bytes
        state.shift_rows()   # Shift Rows
        state.xor(keys[-1])  # Add Round Key
        return state.to_bytes()

    def decrypt_block(self, block: bytes, key: bytes) -> bytes:
        keys = [State(round_key) for round_key in self._ksa(key)][::-1]
        state = State(block)

        # First Round
        state.xor(keys[0])

        # Rest of The Rounds Except Last
        for i in range(1, self.Nr):
            state.shift_rows(inverse=True)  # Inverse Shift Rows
            state = State(self._byte_substitution(state, inverse=True))  # Inverse Substitute Bytes
            state.xor(keys[i])  # Add Round Key
            state.mix_columns(inverse=True)  # Inverse Mix Columns

        # Last Round
        state.shift_rows(inverse=True)  # Inverse Shift Rows
        state = State(self._byte_substitution(state, inverse=True))  # Inverse Substitute Bytes
        state.xor(keys[-1])  # Add Round Key
        return state.to_bytes()


AES_128 = AES(4, 10)
AES_192 = AES(6, 12)
AES_256 = AES(8, 14)
