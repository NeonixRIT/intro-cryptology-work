import sympy as sp
import numpy as np

from block_cipher import BlockCipher, KeyStreamGenerator
from key import Key

from utils import shift_left, shift_right, GF_256_multiply, xor_bits, chunk_string, xor_words, words_to_bytes

MIX_MATRIX = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]

MIX_MATRIX_INV = [
    [0x0e, 0x0b, 0x0d, 0x09],
    [0x09, 0x0e, 0x0b, 0x0d],
    [0x0d, 0x09, 0x0e, 0x0b],
    [0x0b, 0x0d, 0x09, 0x0e]
]

S_BOX = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
]

S_BOX_INV = [
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
]


# Key length to (rounds, key_words, max_rcon)
DATA = {
    128: (10, 4, 9),
    192: (12, 6, 7),
    256: (14, 8, 6),
    'rc': [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
}

IR_POLY = 0x11b


def cols_to_rows_vise_versa(state: list[list[str]]) -> list[list[str]]:
    return [[state[i][j] for i in range(4)] for j in range(4)]


def shift_rows_given_cols(state: list[list[str]], inverse: bool = False) -> list[list[str]]:
    state = cols_to_rows_vise_versa(state)
    shift_func = shift_right if inverse else shift_left
    shifted_rows = [shift_func(state[i], i) for i in range(4)]
    return cols_to_rows_vise_versa(shifted_rows)


def key_chunks_to_key(key_chunks):
    return ''.join(key_chunks[i][j] for i in range(len(key_chunks)) for j in range(len(key_chunks[i])))


class AESKey(Key):
    def __init__(self, key: str, is_string: bool = True):
        self.length = 0
        friendly_string = key if is_string else None
        if is_string:
            if len(key) * 8 not in DATA:
                raise ValueError("Invalid key length")
            word_size = DATA[len(key) * 8][1] * 8
            binary = ''.join([bin(int.from_bytes(letter.encode("utf-8")))[2:].zfill(8) for letter in key])
            self.length = len(binary)
            chunks = chunk_string(binary, word_size)
            self.key = [chunk_string(chunks[i], 8) for i in range(4)]
        else:
            self.length = len(key)
            word_size = DATA[self.length][1] * 8
            chunks = chunk_string(key, word_size)
            self.key = [chunk_string(chunks[i], 8) for i in range(4)]

        if self.length != 128 and self.length != 192 and self.length != 256:
            raise ValueError(f"Invalid key length: {self.length}")

        self.rounds = DATA[self.length][0]
        super().__init__(self.key, friendly_string)


class AESKSA:
    def __init__(self, key: AESKey):
        self.key = key

    def __call__(self):
        return AES_KSA(self.key, self.key.rounds + 1)


def byte_substitution(state: list[list[str]], inverse: bool = False):
    s_box = S_BOX_INV if inverse else S_BOX
    poly_bytes = [b for row in state for b in row] if isinstance(state[0], list) else [s for s in state]
    for i, bits in enumerate(poly_bytes):
        row = int(bits[:4], 2)
        col = int(bits[4:], 2)
        poly_bytes[i] = bin(s_box[row][col])[2:].zfill(8)
    return poly_bytes


def mix_cols(state: list[list[str]], inverse: bool = False) -> list[list[str]]:
    cur_matrix = MIX_MATRIX_INV if inverse else MIX_MATRIX
    state = cols_to_rows_vise_versa(state)
    result = [[0] * len(state[0]) for _ in range(len(cur_matrix))]
    for i in range(len(cur_matrix)):
        for j in range(len(state[0])):
            for k in range(len(state)):
                res = GF_256_multiply(cur_matrix[i][k], int(state[k][j], 2))
                result[i][j] ^= res % 256
    return cols_to_rows_vise_versa(chunk_string([bin(val)[2:].zfill(8) for row in result for val in row], 4))



def AES_encrypt(block: str, ksa: AESKSA, is_string: bool = False, verbose: bool = False):
    rounds = ksa.key.rounds
    ksa = ksa()

    state_as_cols = []
    if is_string:
        state_as_cols = [[bin(int.from_bytes(letter.encode()))[2:].zfill(8) for letter in block[i * 4:4 * (i + 1)]] for i in range(4)]
    else:
        state_as_cols = chunk_string(chunk_string(block, 8), 4)

    # Round 0, only add round key
    k0 = next(ksa)
    binary = ''.join([''.join([bits for bits in col]) for col in state_as_cols])
    state_as_cols = chunk_string(chunk_string(xor_bits(binary, k0), 8), 4)
    if verbose:
        print(f'Plain    : {" ".join(hex(int(val, 2))[2:].zfill(2) for val in chunk_string(binary, 8))}')
        print(f'Round Key: {" ".join(hex(int(val, 2))[2:].zfill(2) for val in chunk_string(k0, 8))}')
        print('\n'.join([' '.join([hex(int(bits, 2))[2:].zfill(2) for bits in col]) for col in cols_to_rows_vise_versa(state_as_cols)]))
        print()

    # Rest of the rounds
    for i in range(rounds):
        # Substitute Bytes
        subbed = chunk_string(byte_substitution(state_as_cols), 4)

        # Shift Rows
        shifted = shift_rows_given_cols(subbed)

        # Mix Columns
        # Last Round, Dont Mix Columns
        if i != rounds - 1:
            mixed = mix_cols(shifted)
        else:
            mixed = shifted

        binary = ''.join([''.join([bits for bits in col]) for col in mixed])

        # Add Round Key
        ki = next(ksa)
        state_as_cols = chunk_string(chunk_string(xor_bits(binary, ki), 8), 4)
        if verbose:
            print(f'Subbed   : {" ".join(hex(int(val, 2))[2:].zfill(2) for val in chunk_string(key_chunks_to_key(subbed), 8))}')
            print(f'Shifted  : {" ".join(hex(int(val, 2))[2:].zfill(2) for val in chunk_string(key_chunks_to_key(shifted), 8))}')
            print(f'Mixed    : {" ".join(hex(int(val, 2))[2:].zfill(2) for val in chunk_string(binary, 8))}')
            print(f'Round Key: {" ".join(hex(int(val, 2))[2:].zfill(2) for val in chunk_string(ki, 8))}')
            print('\n'.join([' '.join([hex(int(bits, 2))[2:].zfill(2) for bits in col]) for col in cols_to_rows_vise_versa(state_as_cols)]))
            print()
    return ''.join([bits for col in state_as_cols for bits in col])


def AES_decrypt(block: str, ksa: AESKSA, is_string: bool = False, verbose: bool = False):
    rounds = ksa.key.rounds
    ksa = ksa()

    state_as_cols = []
    if is_string:
        state_as_cols = [[bin(int.from_bytes(letter.encode()))[2:].zfill(8) for letter in block[i * 4:4 * (i + 1)]] for i in range(4)]
    else:
        state_as_cols = chunk_string(chunk_string(block, 8), 4)

    keys = list(ksa)[::-1]

    # First Round, only add round key
    k0 = keys[0]
    binary = ''.join([''.join([bits for bits in col]) for col in state_as_cols])
    state_as_cols = chunk_string(chunk_string(xor_bits(binary, k0), 8), 4)
    if verbose:
        print(f'Plain    : {" ".join(hex(int(val, 2))[2:].zfill(2) for val in chunk_string(binary, 8))}')
        print(f'Round Key: {" ".join(hex(int(val, 2))[2:].zfill(2) for val in chunk_string(k0, 8))}')
        print('\n'.join([' '.join([hex(int(bits, 2))[2:].zfill(2) for bits in col]) for col in cols_to_rows_vise_versa(state_as_cols)]))
        print()

    # Rest of the rounds
    for i in range(rounds):
        # Shift Rows
        shifted = shift_rows_given_cols(state_as_cols, True)

        # Substitute Bytes
        subbed = chunk_string(byte_substitution(shifted, True), 4)

        # Add Round Key
        ki = keys[i + 1]
        binary = ''.join([''.join([bits for bits in col]) for col in subbed])
        state_as_cols = chunk_string(chunk_string(xor_bits(binary, ki), 8), 4)

        # Mix Columns
        # Last Round, Dont Mix Columns
        if i != rounds - 1:
            mixed = mix_cols(state_as_cols, True)
        else:
            mixed = state_as_cols
        state_as_cols = mixed

        if verbose:
            print(f'Shifted  : {" ".join(hex(int(val, 2))[2:].zfill(2) for val in chunk_string(key_chunks_to_key(shifted), 8))}')
            print(f'Subbed   : {" ".join(hex(int(val, 2))[2:].zfill(2) for val in chunk_string(key_chunks_to_key(subbed), 8))}')
            print(f'Mixed    : {" ".join(hex(int(val, 2))[2:].zfill(2) for val in chunk_string(binary, 8))}')
            print(f'Round Key: {" ".join(hex(int(val, 2))[2:].zfill(2) for val in chunk_string(ki, 8))}')
            print('\n'.join([' '.join([hex(int(bits, 2))[2:].zfill(2) for bits in col]) for col in cols_to_rows_vise_versa(state_as_cols)]))
            print()
    return ''.join([bits for col in state_as_cols for bits in col])


class AESKSA:
    def __init__(self, key: AESKey):
        self.key = key

    def __call__(self):
        return AES_KSA(self.key, self.key.rounds)


def g(word, i, verbose=False):
    shifted = shift_left(word, 1)
    subbed = byte_substitution(shifted)
    subbed[0] = xor_bits(subbed[0], bin(DATA['rc'][i])[2:].zfill(8))
    if verbose:
        print('word   : ', ' '.join([hex(int(w, 2))[2:] for w in word]))
        print('shifted: ', ' '.join([hex(int(word, 2))[2:] for word in shifted]))
        print('subbed : ', ' '.join([hex(int(word, 2))[2:] for word in subbed]))
    return subbed


def AES_KSA(key: Key, rounds: int, verbose: bool = False):
    one = ' '.join([hex(int(word, 2))[2:].zfill(2) for word in key.key[0]])
    two = ' '.join([hex(int(word, 2))[2:].zfill(2) for word in key.key[1]])
    three = ' '.join([hex(int(word, 2))[2:].zfill(2) for word in key.key[2]])
    four = ' '.join([hex(int(word, 2))[2:].zfill(2) for word in key.key[3]])
    if verbose:
        print('Round 00:', one, two, three, four)
    yield key_chunks_to_key(key.key)
    for i in range(rounds):
        ged = g(key.key[3], i, verbose=verbose)
        new_0 = xor_words(tuple(key.key[0]), tuple(ged))
        new_1 = xor_words(tuple(new_0), tuple(key.key[1]))
        new_2 = xor_words(tuple(new_1), tuple(key.key[2]))
        new_3 = xor_words(tuple(new_2), tuple(key.key[3]))
        key.key = [new_0, new_1, new_2, new_3]
        if verbose:
            one = ' '.join([hex(int(word, 2))[2:].zfill(2) for word in new_0])
            two = ' '.join([hex(int(word, 2))[2:].zfill(2) for word in new_1])
            three = ' '.join([hex(int(word, 2))[2:].zfill(2) for word in new_2])
            four = ' '.join([hex(int(word, 2))[2:].zfill(2) for word in new_3])
            print(f'Round {str(i + 1).zfill(2)}: {one} {two} {three} {four}')
        yield key_chunks_to_key(key.key)


class AESCipher(BlockCipher):
    def __init__(self, plaintext: str = None, ciphertext: str = None, key: AESKey = None):
        super().__init__(plaintext, ciphertext, 128, AESKSA(key), AES_encrypt)


# TODO: ENC/DEC Done, Finish AES-128, AES-192 and AES-256

# test_key_128 = [[0x2b, 0x7e, 0x15, 0x16], [0x28, 0xae, 0xd2, 0xa6], [0xab, 0xf7, 0x15, 0x88], [0x09, 0xcf, 0x4f, 0x3c]]
# test_key_128 = ''.join([''.join([bin(val)[2:].zfill(8) for val in row]) for row in test_key_128])
# list(AES_KSA(AESKey(test_key_128, is_string=False), 10, verbose=True))
# print()
# test_key_192 = [[0x8e, 0x73, 0xb0, 0xf7], [0xda, 0x0e, 0x64, 0x52], [0xc8, 0x10, 0xf3, 0x2b], [0x80, 0x90, 0x79, 0xe5], [0x62, 0xf8, 0xea, 0xd2], [0x52, 0x2c, 0x6b, 0x7b]]
# test_key_192 = ''.join([''.join([bin(val)[2:].zfill(8) for val in row]) for row in test_key_192])
# list(AES_KSA(AESKey(test_key_192, is_string=False), 12, verbose=True))
# print()
# test_key_256 = [[], [], [], [], [], [], [], []]
# test_key_256 = ''.join([''.join([bin(val)[2:].zfill(8) for val in row]) for row in test_key_128])
# list(AES_KSA(AESKey(test_key_128, is_string=False), 14, verbose=True))
# print()


class AES:
    def __init__(self, block_size):
        self.block_size = block_size
        self.rounds = DATA[self.block_size][0]
        self.key_size = self.block_size
        self.key_words = DATA[self.block_size][1]
        self.max_rcon = DATA[self.block_size][2]
        self.rcs = DATA['rc']

    def _byte_substitution(self, state: list[bytes] | bytes, inverse: bool = False):
        s_box = S_BOX_INV if inverse else S_BOX
        poly_bytes = [b for row in state for b in row] if isinstance(state[0], list) else [s for s in state]
        for i, byte in enumerate(poly_bytes):
            row = (byte & 0xf0) >> 4
            col = byte & 0x0f
            poly_bytes[i] = s_box[row][col]
        return bytes(poly_bytes)

    def _g(self, word: bytes, i: int):
        shifted = shift_left(word, 1)
        subbed = list(self._byte_substitution(shifted))
        xor_rc = subbed[0] ^ DATA['rc'][i]
        rcond = bytes([xor_rc] + subbed[1:])
        return bytes(rcond)


    def _ksa(self, key: bytes):
        words = [key[i:i + 4] for i in range(0, len(key), 4)]
        yield key[:16]
        temp = words[-1]
        round_key = words[4:]
        round_number = 0
        for i in range(self.max_rcon + 1):
            print(f'Round {i + 1}:')
            for j in range(self.key_words):
                temp = words[-1]
                if j == 0:
                    temp = self._g(temp, i)
                print('\tBEFORE  :', [hex(byte)[2:].zfill(2) for byte in temp])
                print('\tXORED W :', [hex(byte)[2:].zfill(2) for byte in words[j + (i * self.key_words)]])
                temp = xor_words(words[j + (i * self.key_words)], temp)
                print('\tAFTER   :', [hex(byte)[2:].zfill(2) for byte in temp])
                print()
                words.append(temp)
                round_key.append(temp)
                if len(round_key) == 4:
                    yield words_to_bytes(round_key)
                    round_key = []
                    round_number += 1
                if round_number > self.rounds:
                    break


    def encrypt(plain_text: bytes, key: bytes):
        pass

    def decrypt(cipher_text: bytes, key: bytes):
        pass


test_key_128 = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
test_128 = AES(128)
for round_num, round_key in enumerate(list(test_128._ksa(test_key_128))):
    print(f'Round {round_num}:', '', ' '.join([hex(byte)[2:].zfill(2) for byte in bytes(round_key)]))
print('\n')
test_key_192 = bytes([0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b])
test_192 = AES(192)
for round_num, round_key in enumerate(list(test_192._ksa(test_key_192))):
    print(f'Round {round_num}:', '', ' '.join([hex(byte)[2:].zfill(2) for byte in bytes(round_key)]))
print('\n')
# test_key_256 = bytes([0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4])
# test_256 = AES(256)
# for round_num, round_key in enumerate(list(test_256._ksa(test_key_256))):
#     print(f'Round {round_num}:', '', ' '.join([hex(byte)[2:].zfill(2) for byte in bytes(round_key)]))
# TODO: KSA for 128/192 good but MF 256 adds only substitution wtf.
