import math

from random import SystemRandom
from typing import Callable
from utils import big_endian_to_int, int_to_big_endian_bytes
"""
Algorithm Parameterss and Other Variables:
A               -    A state array.

A[x, y, z]      -    For a state array A, the bit that corresponds to the triple
                     (x, y, z).

b               -    The width of a Keccak-p permutation in bits.

c               -    The capacity of a sponge function.

d               -    The length of the digest of a hash function or the requested
                     length of the output of an XOF, in bits.

f               -    The generic underlying function for the sponge construction.

i_r             -    The round index for a Keccak-p permutation.

J               -    The input string to RawSHAKE128 or RawSHAKE256.

L               -    For a Keccak-p permutation, the binary logarithm of the lane size,
                     i.e., log2(w).

Lane(i, j)      -    For a state array A, a string of all the bits of the lane whose x
                     and y coordinates are i and j.

M               -    The input string to a SHA-3 hash or XOF function.

N               -    The input string to Sponge[f, pad, r] or Keccak[c]

n_r             -    The number of rounds for a Keccak-p permutation.

pad             -    The generic padding rule for the sponge construction.

Plane(j)        -    For a state array A, a string of all the bits of the plane whose
                     y coordinate is j.

r               -    The rate of a sponge function.

RC              -    For a round of a Keccak-p permutation, the round constant.

w               -    The lane size of a Keccak-p permutation, in bits, i.e., b/25.


Basic Operations and Functions:
OS(X)           -    For a positive integer s, OS is the string that consists of s
                     consecutive 0s. If s=0 then OS is an empty string.

len(X)          -    For a bit string X, len(X) is the length of X in bits.

X[i]            -    For a string X and an integer i such that 0 ≤ i < len(X), X[i] is
                     the bit of X with index i. Bit strings are depicted with indices
                     increasing from left to right, so that X[0] appears at the left,
                     followed by X[1], etc. For example, if X = 101000, then X[2] = 1.

Truncs(X)       -    For a positive integer s and a string X, Truncs(X) is the string
                     comprised of X[0] to X[s - 1]. For example, Trunc2(10100) = 10.

X ⨁ Y           -    For two strings X and Y of equal bit length, X ⨁ Y is the results
                     from applying the Boolean exclusive-OR operation to X and Y at
                     each bit position. For example, 1100 ⨁ 1010 = 0110.

X || Y          -    For strings X and Y, X || Y is the concatenation of X and Y. For
                     example, 11001 || 010 = 11001010.

m/n             -    For integers m and n, m/n is the quotient, i.e., m divided by n.

m mod n         -    For integers m and n, m mod n is the integer r for which 0 ≤ r < n
                     and m-r is a multiple of n. For example, 11 mod 5 = 1
                     and -11 mod 5 = 4.

⌈x⌉             -    For a real number x, ⌈x⌉ is the least integer that is not strictly
                     less than x. For example, ⌈3.2⌉ = 4, ⌈-3.2⌉ = -3, and ⌈6⌉ = 6.

log2(x)         -    For a positive real number x, log2(x) is the real number y such
                     that 2^y = x.

min(x, y)       -    For real numbers x and y, min(x, y) is the minumum of x and y. For
                     example, min(9, 33) = 9.


Specified Functions:
θ, ⍴, π, χ, ι    -   The five step mappings that comprise a round.

Keccak[c]        -   The Keccak instance with Keccak-f[1600] as the underlying
                     permutation and capacity c.

Keccak-f[b]      -   The family of seven permutaions originally specified in [8] as
                     underlying function as Keccak. The set of values for the width b
                     of the permutations is {25, 50, 100, 200, 400, 800, 1600}.

Keccak-p[b, n_r] -   The generalization of the Keccak-f[b] permutations that is defined
                     in this Standard by converting the number of rounds n_r into an
                     input parameter.

pad10*1          -   The multi-rate padding rule for Keccak, originally specified in
                     [8].

RawSHAKE128      -   An intermedia function in the alternate definition of SHAKE128.

RawSHAKE256      -   An intermedia function in the alternate definition of SHAKE256.

rc               -   The function that generate the variable bits of the round
                     constants.

Rnd              -   The round function of a Keccak-p permutation.

SHA3-224         -   The SHA-3 hash function that produces 224-bit digests.

SHA3-256         -   The SHA-3 hash function that produces 256-bit digests.

SHA3-384         -   The SHA-3 hash function that produces 384-bit digests.

SHA3-512         -   The SHA-3 hash function that produces 512-bit digests.

SHAKE128         -   The SHA-3 XOF that generally supportes 128 bits of security
                     strengh, if the output is sufficiently long; see Sec. A.1.

SHAKE128         -   The SHA-3 XOF that generally supportes 256 bits of security
                     strengh, if the output is sufficiently long; see Sec. A.1.

Sponge[f, pad, r]-   The sponge function in which the underlying function is f, the
                     padding rule is pad, and the rate is r.

State:
State for Keccak-p[b, n_r] permutation is comprised of b bits.
w = b/25 and log2(w) = L.

b   25  50  100 200 400 800 1600
w    1   2    4   8  16  32   64
L    0   1    2   3   4   5    6

5 x 5 x w arrays of bits

Convert Strings to State Arryas:

S = string of b bits

A[x, y, z] = S[w(5y + x) + z]

if b = 1600, so that w = 64, then
    A[0, 0, 0] = S[0]   A[1, 0, 0] = S[64]                  A[4, 0, 0] = S[256]
    A[0, 0, 1] = S[1]   A[1, 0, 1] = S[65]                  A[4, 0, 1] = S[257]
    A[0, 0, 2] = S[2]   A[1, 0, 2] = S[66]                  A[4, 0, 2] = S[258]
            .                   .                                   .
            .                   .               . . .               .
            .                   .                                   .
    A[0, 0, 63] = S[63] A[1, 0, 63] = S[127]                A[4, 0, 63] = S[319]

and

    A[0, 1, 0] = S[320]   A[1, 0, 0] = S[384]                 A[4, 1, 0] = S[576]
    A[0, 1, 1] = S[321]   A[1, 0, 1] = S[385]                 A[4, 1, 1] = S[577]
    A[0, 1, 2] = S[322]   A[1, 0, 2] = S[386]                 A[4, 1, 2] = S[578]
            .                   .                                   .
            .                   .               . . .               .
            .                   .                                   .
    A[0, 1, 63] = S[383] A[1, 0, 63] = S[447]                A[4, 1, 63] = S[639]

and

    A[0, 2, 0] = S[640]   A[1, 0, 0] = S[704]                 A[4, 1, 0] = S[896]
    A[0, 2, 1] = S[641]   A[1, 0, 1] = S[705]                 A[4, 1, 1] = S[897]
    A[0, 2, 2] = S[642]   A[1, 0, 2] = S[706]                 A[4, 1, 2] = S[898]
            .                   .                                   .
            .                   .               . . .               .
            .                   .                                   .
    A[0, 2, 63] = S[703] A[1, 0, 63] = S[767]                A[4, 1, 63] = S[959]

etc.

Convert State Arryas to Strings:

For each pair of integers (i, j) such that 0 ≤ i < 5 and 0 ≤ j < 5, define the string
Lane(i, j) by:

    Lane(i, j) = A[i, j, 0] || A[i, j, 1] || A[i, j, 2] || ... || A[i, j, w-1]

For example, if b = 1600, so that w = 64, then

    Lane(0, 0) = A[0, 0, 0] || A[0, 0, 1] || A[0, 0, 0] || ... || A[0, 0, 63]
    Lane(2, 0) = A[1, 0, 0] || A[1, 0, 1] || A[1, 0, 0] || ... || A[1, 0, 63]
    Lane(3, 0) = A[2, 0, 0] || A[2, 0, 1] || A[2, 0, 0] || ... || A[2, 0, 63]

etc.

For each integer j that 0 ≤ j < 5, define the string Plane(j) by:

    Plane(j) = Lane(0, j) || Lane(1, j) || Lane(2, j) || Lane(3, j) || Lane(4, j).

Then

    S = Plane(0) || Plane(1) || Plane(2) || Plane(3) || Plane(4).

Indexing
    x: 3, 4, 0, 1, 2
    y: 3, 4, 0, 1, 2
    z: 0, 1, 2, 3 ... w - 1

"""
def h2b(H: bytes, n: int = None) -> str:
    '''
    1. For each integer i such that 0 ≤ i < 2m - 1, let Hi be the i-th hexadecimal digit in H:
        H = H0H1H2...H2m-1
    2. For each integer i such that 0 ≤ i < m:
        a. Let hi = 16 * H2i + H2i+1
        b. Let bi0bi1...bi7 be the unique sequence of bits such that
            hi = bi7 * 2^7 + bi6 * 2^6 + bi5 + ... + bi0 * 2^0
    3. For each pair of integers (i, j) such that 0 ≤ i < m and 0 ≤ j < 8, let T[8i + j] = bij:
    4. Return S = Truncn(T).
    '''
    H = hex(big_endian_to_int(H))[2:]
    m = len(H) // 2
    if n is None:
        n = 8 * m

    if not n <= 8 * m:
        raise ValueError('n > 8m')

    bis = []
    for i in range(m):
        hi = 16 * int(H[2 * i], 16) + int(H[2 * i + 1], 16)
        bis += [bin(hi)[2:].zfill(8)]

    return ''.join([bi[::-1] for bi in bis])[:n]


def b2h(S: str) -> str:
    '''
    1. Let n = len(S).
    2. Let T = S || O-n mod 8 and m = ⌈n/8⌉.
    3. For each pair of integers (i, j) such that 0 ≤ i < m and 0 ≤ j < 8, let bij = T[8i + j].
    4. For each integer i such that 0 ≤ i < m:
        a. Let hi = b7i * 2^7 + b6i * 2^6 + b5i + ... + b0i * 2^0.
        b. Let H2i and H2i+1 be the hexadecimal digits such that hi = 16 * H2i + H2i+1.
    5. Return H = H0H1H2...H2m-1.
    '''
    n = len(S)
    T = S + ('0' * (-n % 8))
    m = n // 8 + 1 if n % 8 else n // 8
    res = ''
    for i in range(m):
        hi = T[8 * i:8 * (i + 1)]
        res += hex(int(hi[::-1], 2))[2:].zfill(2)
    return res


def reverse_bits(x: int, n: int) -> int:
    result = 0
    for _ in range(n):
        result <<= 1
        result |= x & 1
        x >>= 1
    return bin(result)[2:].zfill(n)


def right_encode(x: int) -> str:
    if not (0 <= x < 2 ** 2040):
        raise ValueError("x must be in the range [0, 2**2040)")

    n = math.ceil(math.log2(x + 1) / 8) if x > 0 else 1
    reversed_x = reverse_bits(x, n * 8)
    reversed_n = reverse_bits(n, 8)

    return reversed_x + reversed_n


def left_encode(x: int) -> str:
    if not (0 <= x < 2 ** 2040):
        raise ValueError("x must be in the range [0, 2**2040)")

    n = math.ceil(math.log2(x + 1) / 8) if x > 0 else 1
    reversed_x = reverse_bits(x, n * 8)
    reversed_n = reverse_bits(n, 8)

    return reversed_n + reversed_x


def encode_string(S: str) -> str:
    if len(S) > 2 ** 2040:
        raise ValueError("S must be at most 2**2040 bits long")
    return left_encode(len(S)) + S


def bytepad(X: str, w: int) -> str:
    z = left_encode(w) + X
    while len(z) % 8 != 0:
        z += '0'

    while (len(z) // 8) % w != 0:
        z += '00000000'
    return z


def substring(X: str, a: int, b: int):
    if a >= b or a >= len(X):
        return ''
    if b <= len(X):
        return X[a:b]
    return X[a:]


class Row:
    def __init__(self):
        self.__row = [0 for _ in range(5)]

    def __str__(self) -> str:
        return ''.join([str(self[x]) for x in range(5)])

    def __getitem__(self, x: int):
        return self.__row[(x + 2) % 5]

    def __setitem__(self, x: int, v: int):
        self.__row[(x + 2) % 5] = v


class Column:
    def __init__(self):
        self.__col = [0 for _ in range(5)]

    def __str__(self) -> str:
        return '\n'.join([str(self[y]) for y in range(5)])

    def __getitem__(self, y: int):
        return self.__col[(y + 2) % 5]

    def __setitem__(self, y: int, v: int):
        self.__col[(y + 2) % 5] = v


class Lane:
    def __init__(self, w: int):
        self.__lane = [0 for _ in range(w)]

    def __getitem__(self, z: int):
        return self.__lane[z]

    def __setitem__(self, z: int, v: int):
        self.__lane[z] = v


class Plane:
    def __init__(self, w: int):
        self.__plane = [Row() for _ in range(w)]

    def __str__(self) -> str:
        res = ''
        for row in self.__plane:
            res += str(row) + '\n'
        return res

    def __getitem__(self, z: int):
        return self.__plane[z]

    def __setitem__(self, z: int, v: Row):
        self.__plane[z] = v


class Slice:
    def __init__(self):
        self.__slice = [Column() for _ in range(5)]

    def __str__(self) -> str:
        res = ''
        for y in range(5):
            res += str(self.get_row((-y - 3) % 5)) + '\n'
        return res

    def __getitem__(self, x: int):
        return self.__slice[(x + 2) % 5]

    def __setitem__(self, x: int, v: Column):
        self.__slice[(x + 2) % 5] = v

    def get_row(self, y: int) -> Row:
        row = Row()
        for x in range(5):
            row[x] = self[(x - 2) % 5][y]
        return row


class Sheet:
    def __init__(self, w: int):
        self.__sheet = [Lane(w) for _ in range(5)]

    def __str__(self) -> str:
        return '\n'.join([str(lane) for lane in self.__sheet])

    def __getitem__(self, y: int):
        return self.__sheet[(y + 2) % 5]

    def __setitem__(self, y: int, v: Lane):
        self.__sheet[(y + 2) % 5] = v


class State:
    def __init__(self, w: int, S: str = None):
        if 25 * w not in {25, 50, 100, 200, 400, 800, 1600}:
            raise ValueError('w must be 1, 2, 4, 8, 16, 32, or 64')
        self.w = w
        self.b = 25 * w
        self.L = [i for i in range(7) if 2 ** i == w][0]
        self.sheets = [Sheet(w) for _ in range(5)] # index x, y, z
        if S is not None:
            for x in range(5):
                for y in range(5):
                    for z in range(w):
                        self.sheets[(x + 2) % 5][y][z] = int(S[w * (5 * y + x) + z])

    def __str__(self) -> str:
        S = ''
        for y in range(5):
            for x in range(5):
                for z in range(self.w):
                    S += str(self[x][y][z])
        return S

    def __repr__(self) -> str:
        res = ''
        for y in range(5):
            for z in range(self.w):
                res += str(self.get_slice(z).get_row((-y - 3) % 5)) + ' '
            res += '\n'
        return res

    def __getitem__(self, x: int) -> Sheet:
        return self.sheets[(x + 2) % 5]

    def __setitem__(self, x: int, value: Sheet) -> None:
        self.sheets[(x + 2) % 5] = value

    def empty_state(self):
        return State(self.w)

    def copy(self):
        return State(self.w, str(self))

    def get_slice(self, z: int) -> Slice:
        sheet = Slice()
        for x in range(5):
            for y in range(5):
                sheet[x][y] = self[x][y][z]
        return sheet


def theta(A: State) -> State:
    '''
    1. For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w, let:
           C[x, z] = A[x, 0, z] ⨁ A[x, 1, z] ⨁ A[x, 2, z] ⨁ A[x, 3, z] ⨁ A[x, 4, z].
    2. For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w, let:
           D[x, z] = C[x-1 mod 5, z] ⨁ C[x+1 mod 5, z-1 mod w].
    3. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let:
           A'[x, y, z] = A[x, y, z] ⨁ D[x, z].
    4. Return A'.
    '''
    A_prime = A.empty_state()
    w = A_prime.w
    C = Plane(w)
    D = Plane(w)
    for x in range(5):
        for z in range(w):
            C[z][x] = A[x][0][z] ^ A[x][1][z] ^ A[x][2][z] ^ A[x][3][z] ^ A[x][4][z]

    for x in range(5):
        for z in range(w):
            D[z][x] = C[z][(x - 1) % 5] ^ C[(z - 1) % w][(x + 1) % 5]

    for x in range(5):
        for y in range(5):
            for z in range(w):
                A_prime[x][y][z] = A[x][y][z] ^ D[z][x]
    return A_prime


def rho(A: State) -> State:
    '''
    1. For all z such that 0 ≤ z < w, let:
           A'[0, 0, z] = A[0, 0, z].
    2. Let (x, y) = (1, 0).
    3. For t from 0 to 23:
           for all z such that 0 ≤ z < w, let A'[x, y, z] = A[x, y, (z - (t + 1)(t + 2) / 2) mod w].
           let (x, y) = (y, (2x + 3y) mod 5).
    4. Return A'.
    '''
    A_prime = A.empty_state()
    w = A_prime.w
    for z in range(w):
        A_prime[0][0][z] = A[0][0][z]

    x, y = 1, 0
    for t in range(24):
        # print(x, y)
        for z in range(w):
            A_prime[x][y][z] = A[x][y][(z - (t + 1) * (t + 2) // 2) % w]
        x, y = y, (2 * x + 3 * y) % 5
    return A_prime


def pi(A: State) -> State:
    '''
    1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let:
            A'[x, y, z] = A[(x + 3y) mod 5, x, z].
    2. Return A'.
    '''
    A_prime = A.empty_state()
    w = A_prime.w
    for x in range(5):
        for y in range(5):
            for z in range(w):
                A_prime[x][y][z] = A[(x + (3 * y)) % 5][x][z]
    return A_prime


def chi(A: State) -> State:
    '''
    1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let:
           A'[x, y, z] = A[x, y, z] ⨁ ((A[(x + 1) mod 5, y, z] ⨁ 1) & A[(x + 2) mod 5, y, z)]).
    2. Return A'.
    '''
    A_prime = A.empty_state()
    w = A_prime.w
    for x in range(5):
        for y in range(5):
            for z in range(w):
                A_prime[x][y][z] = A[x][y][z] ^ ((A[(x + 1) % 5][y][z] ^ 1) & A[(x + 2) % 5][y][z])
    return A_prime


def rc(t: int) -> int:
    '''
    1. If t mod 255 = 0, return 1.
    2. Let R = 10000000.
    3. For i from 1 to t mod 255, let:
           R = 0 || R.
           R[0] = R[0] ⨁ R[8].
           R[4] = R[4] ⨁ R[8].
           R[5] = R[5] ⨁ R[8].
           R[6] = R[6] ⨁ R[8].
           R = Trunc8(R).
    4. Return R[0].
    '''
    t = t % 255
    if t == 0:
        return 1
    R = [1, 0, 0, 0, 0, 0, 0, 0]
    for _ in range(1, t + 1):
        R = [0] + R
        R[0] ^= R[8]
        R[4] ^= R[8]
        R[5] ^= R[8]
        R[6] ^= R[8]
        R = R[:8]
    return R[0]


def iota(A: State, i_r: int) -> State:
    '''
    1. For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let A'[x, y, z] = A[x, y, z].
    2. Let RC = OW.
    3. For j from 0 to l, let RC[2^j - 1] = rc(j + 7i_r).
    4. For all z such that 0 ≤ z < w, let A'[0, 0, z] = A'[0, 0, z] ⨁ RC[z].
    5. Return A'.
    '''
    A_prime = A.copy()
    w = A_prime.w
    L = A_prime.L
    RC = [0] * w
    for j in range(L + 1):
        RC[(2 ** j) - 1] = rc(j + (7 * i_r))
    for z in range(A_prime.w):
        A_prime[0][0][z] ^= RC[z]
    return A_prime


class Keccak_p:
    def __init__(self, b: int, n_r: int):
        '''
        1. Let L = log2(b / 25).
        2. Let w = 2^L.
        3. Let OW = 00000001.
        4. Let b = 25w.
        5. Let n_r be the number of rounds, which is one of 12 + 2L, 14 + 2L, or 16 + 2L.
        '''
        self.L = [i for i in range(7) if 2 ** i == b / 25][0]
        self.w = 2 ** self.L
        self.b = b
        self.n_r = n_r

    def Rnd(self, A: State, i_r: int) -> State:
        return iota(chi(pi(rho(theta(A)))), i_r)

    def __call__(self, S: str) -> str:
        '''
        1. Convert S into a state array, A, as described in Section 3.1.2.
        2. For i_r from 12 + 2L - n_r to 12 + 2L - 1, let A = Rnd(A, i_r).
        3. Convert A into a string, S' of length b, as described in Section 3.1.3.
        4. Return S'.
        '''
        A = State(self.w, S)
        for i_r in range(self.n_r):
            A = self.Rnd(A, i_r)
        return str(A)


class Keccak_f(Keccak_p):
    def __init__(self, b: int):
        L = [i for i in range(7) if 2 ** i == b / 25][0] # l = log2(b / 25)
        n_r = 12 + 2 * L
        super().__init__(b, n_r)


class Sponge:
    def __init__(self, f: Keccak_p, pad: Callable, r: int):
        self.f = f
        self.pad = pad
        self.r = r

    def __call__(self, N: str, d: int) -> str:
        '''
        1.  Let P = N || pad(r, len(N)).
        2.  Let n = len(P)/r.
        3.  Let c = b - r
        4.  Let P_0, ..., P_n-1 be the unique sequence of strings of length r such that P = P_0 || ... || P_n-1.
        5.  Let S = Ob.
        6.  For i from 0 to n - 1, let S = f(S ⨁ (P_i || Oc)).
        7.  Let Z be the empty string.
        8.  Let Z = Z || Truncr(S).
        9.  If d ≤ |Z|, then return Truncd(Z); else continue.
        10. Let S = f(S), and continue with Step 8
        '''
        P = [int(bit) for bit in (N + self.pad(self.r, len(N)))]
        n = len(P) // self.r
        c = self.f.b - self.r
        Pis = [P[i * self.r:(i + 1) * self.r] for i in range(n)]
        S = [0] * self.f.b
        for i in range(n):
            Pi = Pis[i]
            S = [S[j] ^ (Pi + ([0] * c))[j] for j in range(self.f.b)]
            S = [int(bit) for bit in self.f(S)]

        Z = []
        while True:
            Z = Z + S[:self.r]
            if d <= len(Z):
                return Z[:d]
            S = [int(bit) for bit in self.f(S)]


def pad10x1(x: int, m: int) -> str:
    '''
    1. Let j = (-m - 2) mod x.
    2. Return P = 1 || Oj || 1.
    '''
    j = (-m - 2) % x
    return '1' + ('0' * j) + '1'


class Keccak(Sponge):
    def __init__(self, c: int):
        f = Keccak_f(1600)
        pad = pad10x1
        r = 1600 - c
        super().__init__(f, pad, r)


class SHA3:
    def __init__(self, d: int):
        c = 2 * d
        self.__d = d
        self.__keccak = Keccak(c)

    def __call__(self, M: bytes) -> int:
        M = h2b(M)
        binary = ''.join([str(bit) for bit in self.__keccak(M + '01', self.__d)])
        return int(b2h(binary), 16)


class SHAKE:
    def __init__(self, c: int, d: int):
        if c != 256 and c != 512:
            raise ValueError(f'c must be 256 or 512: {c}')
        self.__d = d
        self.__keccak = Keccak(c)

    def __call__(self, M: bytes) -> str:
        M = h2b(M)
        binary = ''.join([str(bit) for bit in self.__keccak(M + '1111', self.__d)])
        return int(b2h(binary), 16)


class SHAKE128(SHAKE):
    def __init__(self, d: int):
        super().__init__(256, d)


class SHAKE256(SHAKE):
    def __init__(self, d: int):
        super().__init__(512, d)


def sha3(M: bytes, d: int) -> int:
    return SHA3(d)(M)


def shake128(M: bytes, d: int) -> int:
    return SHAKE128(d)(M)


def shake256(M: bytes, d: int) -> int:
    return SHAKE256(d)(M)


class cSHAKE:
    def __init__(self, c: int, L: int, N: str = '', S: str = ''):
        '''
        c = security strength * 2 supported by SHAKE, 256(c=128) or 512(c=256)
        N = Function Name Bit String, S = Customization Bit String
        N is a bit string of a function name defined by NIST.
        if N and S are empty, cSHAKE[c] is identical to SHAKE[c].
        '''
        if c != 256 and c != 512:
            raise ValueError(f'c must be 256 or 512: {c}')
        if len(N) * 8 >= 2 ** 2040 and len(S) * 8 >= 2 ** 2040:
            raise ValueError('Length of bit strings N and S must be less than 2^2040')
        self.c = c
        self.L = L
        self.__keccak = Keccak(c)
        self.N = N
        self.S = S
        self.rate = 168 if c == 256 else 136

    def __call__(self, X: bytes) -> str:
        if not self.N and not self.S:
            return SHAKE(self.c, self.L)(X)
        X = h2b(X)
        X = bytepad(encode_string(self.N) + encode_string(self.S), self.rate) + X + '00'
        binary = ''.join([str(bit) for bit in self.__keccak(X, self.L)])
        return int(b2h(binary), 16)


class cSHAKE128(cSHAKE):
    def __init__(self, L: int, N: str = '', S: str = ''):
        super().__init__(256, L, N, S)


class cSHAKE256(cSHAKE):
    def __init__(self, L: int, N: str = '', S: str = ''):
        super().__init__(512, L, N, S)


class KMAC128:
    def __init__(self, K: str, S: str = ''):
        self.__cSHAKE = cSHAKE128(256, N='11010010101100101000001011000010', S=S)
        self.__K = K

    def __call__(self, X: bytes) -> str:
        X = h2b(X)
        new_X = bytes.fromhex(b2h(bytepad(encode_string(self.__K), self.__cSHAKE.rate) + X + right_encode(self.__cSHAKE.L)))
        return self.__cSHAKE(new_X)


class KMAC256:
    def __init__(self, K: str, S: str = ''):
        self.__cSHAKE = cSHAKE256(512, N='11010010101100101000001011000010', S=S)
        self.__K = K

    def __call__(self, X: bytes) -> str:
        X = h2b(X)
        new_X = bytes.fromhex(b2h(bytepad(encode_string(self.__K), self.__cSHAKE.rate) + X + right_encode(self.__cSHAKE.L)))
        return self.__cSHAKE(new_X)


def sha3_224(M: bytes) -> int:
    return sha3(M, 224)


def sha3_256(M: bytes) -> int:
    return sha3(M, 256)


def sha3_384(M: bytes) -> int:
    return sha3(M, 384)


def sha3_512(M: bytes) -> int:
    return sha3(M, 512)


class PRNG:
    def __init__(self, underlying_hash_function):
        self.__hash_func = underlying_hash_function
        self.__true_rng = SystemRandom()

    def random_bytes(self, n: int, seed: bytes = None) -> bytes:
        '''
        n: number of bytes to generate
        Generate and return n pseudo-random bytes
        '''
        if n < 0:
            raise ValueError('n must be non-negative')
        if n == 0:
            return b''
        seed = seed if seed is not None else self.__true_rng.randbytes(32)
        d = n * 8 + (8 - n * 8 % 8)
        return int_to_big_endian_bytes(self.__hash_func(seed, d))[:n]

    def random_bits(self, n: int, seed: bytes = None) -> str:
        '''
        n: number of bits to generate
        Generate and return a pseudo-random bit string of length n
        '''
        seed = seed if seed is not None else self.__true_rng.randbytes(32)
        d = n + (8 - n % 8)
        return bin(self.__hash_func(seed, d)).zfill(d)[2:n + 2]


prng_shake128 = PRNG(shake128)
prng_shake256 = PRNG(shake256)


def main():
    from hashlib import sha3_224, sha3_256, sha3_384, sha3_512, shake_128, shake_256
    light_red = '\033[91m'
    light_green = '\033[92m'
    light_yellow = '\033[93m'
    white = '\033[0m'

    test_vector_all = [(224, sha3, sha3_224), (256, sha3, sha3_256), (384, sha3, sha3_384), (512, sha3, sha3_512)]
    test_vector = test_vector_all
    for message in ['The quick brown fox jumps over the lazy dog', 'Some other dumb sentence that I made up thats really long because I want multiple runs in the function just to make sure that it works well', 'abc', '']:
        print(f'{light_yellow}Message: `{message}`{white}')
        for out_len, my_func, test_func in test_vector:
            print(f'\tSHA 3 {out_len}:')
            inp = message.encode()
            raw_actual = hex(my_func(inp, out_len))[2:]
            raw_expected = test_func(inp).hexdigest()
            actual = int(raw_actual, 16)
            expected = int(raw_expected, 16)
            print(f'\t\tactual:   {raw_actual}')
            print(f'\t\texpected: {raw_expected}')
            try:
                assert actual == expected
                print(f'\t{light_green}Success!{white}\n')
            except AssertionError:
                print(f'\t{light_red}Failure!{white}\n')
    print()
    test_vector_all = [(128, shake128, shake_128), (256, shake256, shake_256)]
    test_vector = test_vector_all
    for i in range(1, 3):
        for message in ['The quick brown fox jumps over the lazy dog', 'Some other dumb sentence that I made up thats really long because I want multiple runs in the function just to make sure that it works well', 'abc', '']:
            print(f'{light_yellow}Message: `{message}`{white}')
            for out_len, my_func, test_func in test_vector:
                print(f'\tSHAKE {out_len} {out_len * i}:')
                inp = message.encode()
                raw_actual = hex(my_func(inp, out_len * i))[2:]
                raw_expected = test_func(inp).hexdigest(out_len // 8 * i)
                actual = int(raw_actual, 16)
                expected = int(raw_expected, 16)
                print(f'\t\tactual:   {raw_actual}')
                print(f'\t\texpected: {raw_expected}')
                try:
                    assert actual == expected
                    print(f'\t{light_green}Success!{white}\n')
                except AssertionError:
                    print(f'\t{light_red}Failure!{white}\n')


if __name__ == '__main__':
    main()
