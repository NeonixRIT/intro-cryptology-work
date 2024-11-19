"""
A collision attack published in 2007 can find collisions for full MD4 in less than 2 hash operations.

test vectors
MD4 ("") = 31d6cfe0d16ae931b73c59d7e0c089c0
MD4 ("a") = bde52cb31de33e46245e05fbdbd6fb24
MD4 ("abc") = a448017aaf21d8525fc10ae87aa6729d
MD4 ("message digest") = d9130a8164549fe818874806e1c7014b
MD4 ("abcdefghijklmnopqrstuvwxyz") = d79e1c308aa5bbcdeea8ed63df412da9
MD4 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") = 043f8582f241db351ce627e153e7f0e4
MD4 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890") = e33b4ddc9c38f2199c3e7b164fcc0536

k1 = 839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edd45e51fe39708bf9427e9c3e8b9
k2 = 839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edc45e51fe39708bf9427e9c3e8b9

k1 ≠ k2, but MD4(k1) = MD4(k2) = 4d7e6a1defa93d2dde05b45d864c429b

output length: 128 bits (16 bytes)
block size: 512 bits (64 bytes)
rounds: 3
resources:
    - https://en.wikipedia.org/wiki/MD4
    - https://datatracker.ietf.org/doc/html/rfc1186

Step 1. Append padding bits
Step 2. Append length
Step 3. Initialize MD buffer
Step 4. Process message in 16-word blocks
Step 5. Output

Step 1. Append padding bits
    The message is "padded" (extended) so that its length (in bits)
    is congruent to 448, modulo 512.  That is, the message is
    extended so that it is just 64 bits shy of being a multiple of
    512 bits long.  Padding is always performed, even if the length
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

Step 3. Initialize MD buffer
    A 4-word buffer (A,B,C,D) is used to compute the message
    digest.  Here each of A,B,C,D are 32-bit registers.  These
    registers are initialized to the following values in
    hexadecimal, low-order bytes first):

    word A:    01 23 45 67
    word B:    89 ab cd ef
    word C:    fe dc ba 98
    word D:    76 54 32 10

Step 4. Process message in 16-word blocks
    We first define three auxiliary functions that each take
    as input three 32-bit words and produce as output one
    32-bit word.

    f(X,Y,Z)  =  XY v not(X)Z
    g(X,Y,Z)  =  XY v XZ v YZ
    h(X,Y,Z)  =  X xor Y xor Z

    In each bit position f acts as a conditional: if x then y else
    z.  (The function f could have been defined using + instead of
    v since XY and not(X)Z will never have 1's in the same bit
    position.)  In each bit position g acts as a majority function:
    if at least two of x, y, z are on, then g has a one in that bit
    position, else g has a zero. It is interesting to note that if
    the bits of X, Y, and Z are independent and unbiased, the each
    bit of f(X,Y,Z) will be independent and unbiased, and similarly
    each bit of g(X,Y,Z) will be independent and unbiased.  The
    function h is the bit-wise "xor" or "parity" function; it has
    properties similar to those of f and g.

    Do the following:

    For i = 0 to N/16-1 do  /* process each 16-word block */
            For j = 0 to 15 do: /* copy block i into X */
                Set X[j] to M[i*16+j].
            end /* of loop on j */
            Save A as AA, B as BB, C as CC, and D as DD.

            [Round 1]
            Let [A B C D i s] denote the operation
                    A = (A + f(B,C,D) + X[i]) <<< s  .
            Do the following 16 operations:
                    [A B C D 0 3]
                    [D A B C 1 7]
                    [C D A B 2 11]
                    [B C D A 3 19]
                    [A B C D 4 3]
                    [D A B C 5 7]
                    [C D A B 6 11]
                    [B C D A 7 19]
                    [A B C D 8 3]
                    [D A B C 9 7]
                    [C D A B 10 11]
                    [B C D A 11 19]
                    [A B C D 12 3]
                    [D A B C 13 7]
                    [C D A B 14 11]
                    [B C D A 15 19]

            [Round 2]
            Let [A B C D i s] denote the operation
                    A = (A + g(B,C,D) + X[i] + 5A827999) <<< s .
            (The value 5A..99 is a hexadecimal 32-bit
            constant, written with the high-order digit
            first. This constant represents the square
            root of 2.  The octal value of this constant
            is 013240474631.  See Knuth, The Art of
            Programming, Volume 2 (Seminumerical
            Algorithms), Second Edition (1981),
            Addison-Wesley.  Table 2, page 660.)
            Do the following 16 operations:
                    [A B C D 0  3]
                    [D A B C 4  5]
                    [C D A B 8  9]
                    [B C D A 12 13]
                    [A B C D 1  3]
                    [D A B C 5  5]
                    [C D A B 9  9]
                    [B C D A 13 13]
                    [A B C D 2  3]
                    [D A B C 6  5]
                    [C D A B 10 9]
                    [B C D A 14 13]
                    [A B C D 3  3]
                    [D A B C 7  5]
                    [C D A B 11 9]
                    [B C D A 15 13]

            [Round 3]
            Let [A B C D i s] denote the operation
                    A = (A + h(B,C,D) + X[i] + 6ED9EBA1) <<< s .
            (The value 6E..A1 is a hexadecimal 32-bit
            constant, written with the high-order digit
            first.  This constant represents the square
            root of 3.  The octal value of this constant
            is 015666365641.  See Knuth, The Art of
            Programming, Volume 2 (Seminumerical
            Algorithms), Second Edition (1981),
            Addison-Wesley.  Table 2, page 660.)
            Do the following 16 operations:
                    [A B C D 0  3]
                    [D A B C 8  9]
                    [C D A B 4  11]
                    [B C D A 12 15]
                    [A B C D 2  3]
                    [D A B C 10 9]
                    [C D A B 6  11]
                    [B C D A 14 15]
                    [A B C D 1  3]
                    [D A B C 9  9]
                    [C D A B 5  11]
                    [B C D A 13 15]
                    [A B C D 3  3]
                    [D A B C 11 9]
                    [C D A B 7  11]
                    [B C D A 15 15]

    Then perform the following additions:
                    A = A + AA
                    B = B + BB
                    C = C + CC
                    D = D + DD
    (That is, each of the four registers is incremented by
    the value it had before this block was started.)

    end /* of loop on i */

Step 5. Output
    The message digest produced as output is A,B,C,D.  That is, we
    begin with the low-order byte of A, and end with the high-order
    byte of D.

    This completes the description of MD4.  A reference
    implementation in C is given in the Appendix.
"""

ANDY = 0xFFFFFFFF
BLOCK_SIZE = 64


def int_to_bytes(number: int, size: int = None, endian: str = 'little', signed=False) -> bytes:
    if size is None:
        size = (number.bit_length() + 7) // 8
    return number.to_bytes(size, endian, signed=signed)


def rotl(num: int, bits: int, zfill_len: int):
    # bits %= zfill_len
    # if bits == 0:
    #     return num
    return (num << bits) | (num >> (zfill_len - bits))


def pad(data: bytes) -> bytes:
    """
    Step 1. Append padding bits
        The message is "padded" (extended) so that its length (in bits)
        is congruent to 448, modulo 512.  That is, the message is
        extended so that it is just 64 bits shy of being a multiple of
        512 bits long.  Padding is always performed, even if the length
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
    input_len_bytes = int_to_bytes(((input_len * 8) % (2**64)), 8)[:8]
    padding_len = abs(BLOCK_SIZE - ((input_len + 9) % BLOCK_SIZE))
    padding = (b'\x80' + (b'\x00' * padding_len)) + (input_len_bytes)
    padding += b'\x00' * (8 - len(input_len_bytes))
    assert len(data + padding) % BLOCK_SIZE == 0
    return data + padding


def f(X: int, Y: int, Z: int):
    """
    X, Y, Z are 32-bit words
    output is a 32-bit word

    f(X, Y, Z)  =  XY v not(X)Z
    (X & Y) + ((~X) & Z)
    In each bit position acts as a conditional:
        if x then y else z # y if x else z
    """
    return (X & Y) | (~X & Z)


def ff(A, B, C, D, X, i, s):
    """
    A = (A + f(B,C,D) + X[i]) <<< s
    """
    return rotl((A + f(B, C, D) + X[i]) & ANDY, s, 32)


def g(X, Y, Z):
    """
    g(X, Y, Z)  =  XY v XZ v YZ
    (X & Y) | (X & Z) | (Y & Z)
    In each bit position acts as a majority function:
        if at least two of x, y, z are on, then g has a one in that bit
        position, else g has a zero.
    """
    return (X & Y) | (X & Z) | (Y & Z)


def gg(A, B, C, D, X, i, s):
    """
    A = (A + g(B,C,D) + X[i] + 5A827999) <<< s
    """
    return rotl((A + g(B, C, D) + X[i] + 0x5A827999) & ANDY, s, 32)


def h(X, Y, Z):
    """
    h(X, Y, Z)  =  X xor Y xor Z
    X ^ Y ^ Z
    The function h is the bit-wise "xor" or "parity" function:
        it has properties similar to those of f and g.
    """
    return X ^ Y ^ Z


def hh(A, B, C, D, X, i, s):
    """
    A = (A + h(B,C,D) + X[i] + 6ED9EBA1) <<< s
    """
    return rotl((A + h(B, C, D) + X[i] + 0x6ED9EBA1) & ANDY, s, 32)


def md4(data: bytes) -> int:
    """
    Step 3. Initialize MD buffer
    A 4-word buffer (A,B,C,D) is used to compute the message
    digest.  Here each of A,B,C,D are 32-bit registers.  These
    registers are initialized to the following values in
    hexadecimal, low-order bytes first):

    word A:    01 23 45 67
    word B:    89 ab cd ef
    word C:    fe dc ba 98
    word D:    76 54 32 10
    """
    padded_data = pad(data)
    blocks = (
        [
            padded_data[j * BLOCK_SIZE : (j + 1) * BLOCK_SIZE][i]
            | padded_data[j * BLOCK_SIZE : (j + 1) * BLOCK_SIZE][i + 1] << 8
            | padded_data[j * BLOCK_SIZE : (j + 1) * BLOCK_SIZE][i + 2] << 16
            | padded_data[j * BLOCK_SIZE : (j + 1) * BLOCK_SIZE][i + 3] << 24
            for i in range(0, len(padded_data[j * BLOCK_SIZE : (j + 1) * BLOCK_SIZE]), 4)
        ]
        for j in range((int(len(padded_data) + 0.5) // BLOCK_SIZE))
    )

    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for X in blocks:  # process each 16-word block (512 bits)
        AA, BB, CC, DD = A, B, C, D

        # Round 1
        idxs = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        S = [3, 7, 11, 19]
        for i, idx in enumerate(idxs):
            A, B, C, D = D, ff(A, B, C, D, X, idx, S[i % 4]), B, C

        # Round 2
        idxs = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        S = [3, 5, 9, 13]
        for i, idx in enumerate(idxs):
            A, B, C, D = D, gg(A, B, C, D, X, idx, S[i % 4]), B, C

        # Round 3
        idxs = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        S = [3, 9, 11, 15]
        for i, idx in enumerate(idxs):
            A, B, C, D = D, hh(A, B, C, D, X, idx, S[i % 4]), B, C

        A = (A + AA) & ANDY
        B = (B + BB) & ANDY
        C = (C + CC) & ANDY
        D = (D + DD) & ANDY
    return A | B << 32 | C << 64 | D << 96


if __name__ == '__main__':
    from random import randbytes

    for _ in range(1000):
        pt = randbytes(1000)
        res = md4(pt)
    # print(int_to_bytes(md4(b''), 16).hex().upper() == '31D6CFE0D16AE931B73C59D7E0C089C0')
    # print(int_to_bytes(md4(b'a'), 16).hex().upper() == 'bde52cb31de33e46245e05fbdbd6fb24'.upper())
    # print(int_to_bytes(md4(b'abc'), 16).hex().upper() == 'A448017AAF21D8525FC10AE87AA6729D')
    # print(int_to_bytes(md4(b'message digest'), 16).hex().upper() == 'D9130A8164549FE818874806E1C7014B')
    # print(int_to_bytes(md4(b'abcdefghijklmnopqrstuvwxyz'), 16).hex().upper() == 'D79E1C308AA5BBCDEEA8ED63DF412DA9')
    # print(int_to_bytes(md4(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'), 16).hex().upper() == '043F8582F241DB351CE627E153E7F0E4')
    # print(int_to_bytes(md4(b'12345678901234567890123456789012345678901234567890123456789012345678901234567890'), 16).hex().upper() == 'E33B4DDC9C38F2199C3E7B164FCC0536')
    # k1 = md4(b'\x83\x9c\x7a\x4d\x7a\x92\xcb\x56\x78\xa5\xd5\xb9\xee\xa5\xa7\x57\x3c\x8a\x74\xde\xb3\x66\xc3\xdc\x20\xa0\x83\xb6\x9f\x5d\x2a\x3b\xb3\x71\x9d\xc6\x98\x91\xe9\xf9\x5e\x80\x9f\xd7\xe8\xb2\x3b\xa6\x31\x8e\xdd\x45\xe5\x1f\xe3\x97\x08\xbf\x94\x27\xe9\xc3\xe8\xb9')
    # k2 = md4(b'\x83\x9c\x7a\x4d\x7a\x92\xcb\xd6\x78\xa5\xd5\x29\xee\xa5\xa7\x57\x3c\x8a\x74\xde\xb3\x66\xc3\xdc\x20\xa0\x83\xb6\x9f\x5d\x2a\x3b\xb3\x71\x9d\xc6\x98\x91\xe9\xf9\x5e\x80\x9f\xd7\xe8\xb2\x3b\xa6\x31\x8e\xdc\x45\xe5\x1f\xe3\x97\x08\xbf\x94\x27\xe9\xc3\xe8\xb9')
    # print(k1 == k2)
    # NTHash has is just the password encoded in UTF-16LE and hashed with MD4
    # print(int_to_bytes(md4('NewStudent123'.encode('UTF-16LE'))).hex().upper())
    # LM Hash used TDES
