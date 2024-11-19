"""
Updated version of MD algorithm to address weaknesses in MD4
Adds one additional round and adjusts the process of each round
"""

from math import floor, sin

ANDY = 0xFFFFFFFF
PAD_LIMIT = 0x10000000000000000
BLOCK_SIZE = 64

S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]
T = [floor(pow(2, 32) * abs(sin(i))) for i in range(1, 65)]


def int_to_bytes(number: int, size: int = None, endian: str = 'little', signed=False) -> bytes:
    if size is None:
        size = (number.bit_length() + 7) // 8
    return number.to_bytes(size, endian, signed=signed)


def rotl(num: int, bits: int, zfill_len: int):
    return (num << bits) | (num >> (zfill_len - bits))


def pad(data: bytes) -> bytes:
    """
    Step 1. Append padding bits
        The message is "padded" (extended) so that its length (in bits)
        is congruent to 448, modulo 512.  That is, the message is
        extended so that it is just 64 bits shy of being a multiple of
        512 bits long.  Padding is always performeD, even if the length
        of the message is already congruent to 448, modulo 512 (in
        which case 512 bits of padding are added).
        Padding is performed as follows: a single "1" bit is appended
        to the message, and then enough zero bits are appended so that
        the length in bits of the padded message becomes congruent to
        448, modulo 512.

    Step 2. Append length
        A 64-bit representation of b (the length of the message before
        the padding bits were added) is appended to the result of the
        previous step.  In the unlikely event that b is greater than
        2^64, then only the low-order 64 bits of b are used.  (These
        bits are appended as two 32-bit words and appended low-order
        word first in accordance with the previous conventions.)

        At this point the resulting message (after padding with bits
        and with b) has a length that is an exact multiple of 512 bits.
        Equivalently, this message has a length that is an exact
        multiple of 16 (32-bit) words.  Let M[0 ... N-1] denote the
        words of the resulting message, where N is a multiple of 16.
    """
    input_len = len(data)
    input_len_bytes = int_to_bytes(((input_len * 8) % PAD_LIMIT), 8)
    data += b'\x80'
    data += b'\x00' * ((BLOCK_SIZE - 8 - len(data)) % BLOCK_SIZE)
    data += input_len_bytes

    return data


def F(X: int, Y: int, Z: int):
    return (X & Y) | ((~X) & Z)


def FF(A, B, C, D, Xk, s, Ti):
    """
    A = B + ((A + f(B,C,D) + X[k] + T[i]) <<< s)
    """
    A = (A + F(B, C, D) + Xk + Ti) & ANDY
    A = (B + rotl(A, s, 32)) & ANDY
    return D, A, B, C


def G(X, Y, Z):
    return (X & Z) | (Y & (~Z))


def GG(A, B, C, D, Xk, s, Ti):
    """
    A = B + ((A + g(B,C,D) + X[k] + T[i]) <<< s)
    """
    A = (A + G(B, C, D) + Xk + Ti) & ANDY
    A = (B + rotl(A, s, 32)) & ANDY
    return D, A, B, C


def H(X, Y, Z):
    """
    h(X, Y, Z)  =  X xor Y xor Z
    X ^ Y ^ Z
    The function h is the bit-wise "xor" or "parity" function:
        it has properties similar to those of f and g.
    """
    return X ^ Y ^ Z


def HH(A, B, C, D, Xk, s, Ti):
    """
    A = B + (A + h(B,C,D) + X[k] + T[i]) <<< s)
    """
    A = (A + H(B, C, D) + Xk + Ti) & ANDY
    A = (B + rotl(A, s, 32)) & ANDY
    return D, A, B, C


def I(X, Y, Z):
    """
    i(X, Y, Z)  =  Y xor (X v not(Z))
    Y ^ (X | ~Z)
    The function i is the bit-wise "xor" function:
        it takes the value of x if x is the majority value for the
        majority of the bits, and the value of y otherwise.
    """
    return Y ^ (X | (~Z))


def II(A, B, C, D, Xk, s, Ti):
    """
    A = B + (A + i(B,C,D) + X[k] + T[i]) <<< s)
    """
    A = (A + I(B, C, D) + Xk + Ti) & ANDY
    A = (B + rotl(A, s, 32)) & ANDY
    return D, A, B, C


def md5(data: bytes) -> int:
    padded_data = pad(data)
    # print(padded_data.hex())
    blocks = (
        [
            padded_data[j * BLOCK_SIZE : (j + 1) * BLOCK_SIZE][i]
            | padded_data[j * BLOCK_SIZE : (j + 1) * BLOCK_SIZE][i + 1] << 8
            | padded_data[j * BLOCK_SIZE : (j + 1) * BLOCK_SIZE][i + 2] << 16
            | padded_data[j * BLOCK_SIZE : (j + 1) * BLOCK_SIZE][i + 3] << 24
            for i in range(0, len(padded_data[j * BLOCK_SIZE : (j + 1) * BLOCK_SIZE]), 4)
        ]
        for j in range(int((len(padded_data) + 0.5) // BLOCK_SIZE))
    )
    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for X in blocks:  # process each 16-word block (512 bits)
        AA, BB, CC, DD = A, B, C, D

        # Round 1
        ks = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        S = [7, 12, 17, 22]
        idxs = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        for i, idx in enumerate(idxs):
            A, B, C, D = FF(A, B, C, D, X[ks[i]], S[i % 4], T[idx])

        # Round 2
        ks = [1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12]
        S = [5, 9, 14, 20]
        idxs = [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
        for i, idx in enumerate(idxs):
            (
                A,
                B,
                C,
                D,
            ) = GG(A, B, C, D, X[ks[i]], S[i % 4], T[idx])

        # Round 3
        ks = [5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2]
        S = [4, 11, 16, 23]
        idxs = [32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47]
        for i, idx in enumerate(idxs):
            A, B, C, D = HH(A, B, C, D, X[ks[i]], S[i % 4], T[idx])

        # Round 4
        ks = [0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9]
        S = [6, 10, 15, 21]
        idxs = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63]
        for i, idx in enumerate(idxs):
            A, B, C, D = II(A, B, C, D, X[ks[i]], S[i % 4], T[idx])

        A = (A + AA) & ANDY
        B = (B + BB) & ANDY
        C = (C + CC) & ANDY
        D = (D + DD) & ANDY
    return A | B << 32 | C << 64 | D << 96


"""
def md5_2(data: bytes) -> int:
    padded_data = pad(data)
    blocks = (
        [
            padded_data[j * BLOCK_SIZE: (j + 1) * BLOCK_SIZE][i] | padded_data[j * BLOCK_SIZE: (j + 1) * BLOCK_SIZE][i + 1] << 8 | padded_data[j * BLOCK_SIZE: (j + 1) * BLOCK_SIZE][i + 2] << 16 | padded_data[j * BLOCK_SIZE: (j + 1) * BLOCK_SIZE][i + 3] << 24
            for i in range(0, len(padded_data[j * BLOCK_SIZE: (j + 1) * BLOCK_SIZE]), 4)
        ]
        for j in range(int((len(padded_data) + 0.5) // BLOCK_SIZE))
    )
    A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    for X in blocks: # process each 16-word block (512 bits)
        AA, BB, CC, DD = A, B, C, D
        for i in range(64):
            F = 0
            g = 0
            if 0 <= i <= 15:
                F = (B & C) | ((~B) & D)
                g = i
            elif 16 <= i <= 31:
                F = (D & B) | ((~D) & C)
                g = (5 * i + 1) % 16
            elif 32 <= i <= 47:
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
            elif 48 <= i <= 63:
                F = C ^ (B | (~D))
                g = (7 * i) % 16
            F = (F + A + T[i] + X[g]) & ANDY
            A, B, C, D = D, (B + rotl(F, S[i], 32)) & ANDY, B, C

        A = (A + AA) & ANDY
        B = (B + BB) & ANDY
        C = (C + CC) & ANDY
        D = (D + DD) & ANDY
    return A | B << 32 | C << 64 | D << 96
"""


if __name__ == '__main__':
    from time import perf_counter
    from random import randbytes, choice, seed

    import hashlib

    start = perf_counter()
    tests = 100000
    current_test = 1
    len_range = range(0, 1000)
    seed(0)
    try:
        while current_test < tests + 1:
            byte_gen_start = perf_counter()
            pt = randbytes(choice(len_range))
            byte_gen_end = perf_counter()
            hashlib_md5_start = perf_counter()
            expected = hashlib.md5(pt).hexdigest().upper().ljust(32, '0')
            hashlib_md5_end = perf_counter()
            start += (byte_gen_end - byte_gen_start) + (hashlib_md5_end - hashlib_md5_start)
            actual = int_to_bytes(md5(pt), 16).hex().upper().ljust(32, '0')
            assert expected == actual
            current_test += 1
    except AssertionError:
        print(f'Failed on test {current_test} of {tests}.')
        print(f'Failed: {expected} != {actual}')
        # print(f'\tPT: {pt}')
        print(f'\tLen     : {len(pt)}')
        print(f'\tActual  : {actual}')
        print(f'\tExpected: {expected}')
    else:
        print(f'Passed {tests} tests in {perf_counter() - start:.2f} seconds')
