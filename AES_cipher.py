import sympy as sp
import numpy as np

from block_cipher import BlockCipher, KeyStreamGenerator
from key import Key

from utils import letter_to_poly, shift_left, poly_to_letter, poly_to_byte, bits_to_poly, xor_bits, chunk_string, xor_words, string_to_bits

one_poly = 1
two_poly = letter_to_poly(chr(2))
three_poly = letter_to_poly(chr(3))

MIX_MATRIX = [[0x02, 0x03, 0x01, 0x01], [0x01, 0x02, 0x03, 0x01], [0x01, 0x01, 0x02, 0x03], [0x03, 0x01, 0x01, 0x02]]


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

IR_POLY = int('100011011', 2)


def cols_to_rows_vise_versa(state: list[list[str]]) -> list[list[str]]:
    return [[state[i][j] for i in range(4)] for j in range(4)]


def shift_rows_given_cols(state: list[list[str]]) -> list[list[str]]:
    state = cols_to_rows_vise_versa(state)
    shifted_rows = [shift_left(state[i], i) for i in range(4)]
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


def byte_substitution(state: list[list[sp.Poly]], encrypt: bool = True):
    s_box = S_BOX if encrypt else S_BOX_INV
    poly_bytes = [b for row in state for b in row] if isinstance(state[0], list) else [s for s in state]
    for i, bits in enumerate(poly_bytes):
        row = int(bits[:4], 2)
        col = int(bits[4:], 2)
        poly_bytes[i] = bin(s_box[row][col])[2:].zfill(8)
    return poly_bytes


def mix_cols(state: list[list[sp.Poly]]):
    state = cols_to_rows_vise_versa(state)
    result = [[0] * len(state[0]) for _ in range(len(MIX_MATRIX))]
    for i in range(len(MIX_MATRIX)):
        for j in range(len(state[0])):
            for k in range(len(state)):
                res = MIX_MATRIX[i][k] * int(state[k][j], 2) if MIX_MATRIX[i][k] != 3 else int(state[k][j], 2) * 2 ^ int(state[k][j], 2)
                result[i][j] ^= res
    return cols_to_rows_vise_versa(chunk_string([bin(val if val < 256 else val ^ IR_POLY)[2:].zfill(8) for row in result for val in row], 4))


def AES_round_function(block: str, ksa: AESKSA, encrypt: bool = True, verbose: bool = False):
    rounds = ksa.key.rounds
    ksa = ksa()

    state_as_cols = [[bin(int.from_bytes(letter.encode()))[2:].zfill(8) for letter in block[i * 4:4 * (i + 1)]] for i in range(4)]

    # Round 0
    k0 = next(ksa)
    binary = ''.join([''.join([bits for bits in col]) for col in state_as_cols])
    state_as_cols = chunk_string(chunk_string(xor_bits(binary, k0), 8), 4)
    if verbose:
        print(f'Round Key: {" ".join(hex(int(val, 2))[2:].zfill(2) for val in chunk_string(k0, 8))}')
        print(f'Plain    : {" ".join(hex(int(val, 2))[2:].zfill(2) for val in chunk_string(binary, 8))}')
        print('\n'.join([' '.join([hex(int(bits, 2))[2:].zfill(2) for bits in col]) for col in cols_to_rows_vise_versa(state_as_cols)]))
        print()
    for i in range(rounds):
        subbed = chunk_string(byte_substitution(state_as_cols, encrypt), 4)
        shifted = shift_rows_given_cols(subbed)
        if i != rounds - 1:
            mixed = mix_cols(shifted)
        else:
            mixed = shifted
        binary = ''.join([''.join([bits for bits in col]) for col in mixed])
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
        ged = g(key.key[3], i)
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
    pass


AES_round_function('Two One Nine Two', AESKSA(AESKey('Thats my Kung Fu')), verbose=True)
# AESKey("abcdefghijklmnop")
# AESKey("abcdefghijklmnopqrstuvws")