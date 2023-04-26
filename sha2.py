from utils import chunk_string


def rotr(num, bits, zfill_len: int):
    bits %= zfill_len
    if bits == 0:
        return num

    return (num >> bits) | ((num << zfill_len - bits))


def shr(num, bits):
    return num >> bits


HIS_224 = (
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
)

HIS_256 = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
)

KIS_224_256 = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
)

HIS_384 = (
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
)

HIS_512 = (
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
)

KIS_384_512 = (
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
)


class SHA2Constant:
    def __init__(self, out_len):
        if out_len not in {224, 256, 384, 512}:
            raise ValueError(f'Invalid output length {out_len}: SHA 2 only supports 224, 256, 384, and 512 bit output.')

        self.__out_len = out_len
        self.parent_out = 256 if out_len <= 256 else 512
        self.chunk_size = 512 if out_len <= 256 else 1024
        self.padding_mod = self.chunk_size
        self.padding_int_bits = 64 if out_len <= 256 else 128
        self.word_size = 32 if out_len <= 256 else 64
        self.addition_mod = 2 ** self.word_size

        match out_len:
            case 224:
                self.iv = HIS_224
                self.k = KIS_224_256
                self.hi_len = 7
            case 256:
                self.iv = HIS_256
                self.k = KIS_224_256
                self.hi_len = 8
            case 384:
                self.iv = HIS_384
                self.k = KIS_384_512
                self.hi_len = 6
            case 512:
                self.iv = HIS_512
                self.k = KIS_384_512
                self.hi_len = 8
        self.rounds = len(self.k)

        if out_len <= 256:
            self.theta_0 = lambda x: rotr(x, 7, self.word_size) ^ rotr(x, 18, self.word_size) ^ shr(x, 3)
            self.theta_1 = lambda x: rotr(x, 17, self.word_size) ^ rotr(x, 19, self.word_size) ^ shr(x, 10)
            self.sig_0 = lambda x: rotr(x, 2, self.word_size) ^ rotr(x, 13, self.word_size) ^ rotr(x, 22, self.word_size)
            self.sig_1 = lambda x: rotr(x, 6, self.word_size) ^ rotr(x, 11, self.word_size) ^ rotr(x, 25, self.word_size)
        else:
            self.theta_0 = lambda x: rotr(x, 1, self.word_size) ^ rotr(x, 8, self.word_size) ^ shr(x, 7)
            self.theta_1 = lambda x: rotr(x, 19, self.word_size) ^ rotr(x, 61, self.word_size) ^ shr(x, 6)
            self.sig_0 = lambda x: rotr(x, 28, self.word_size) ^ rotr(x, 34, self.word_size) ^ rotr(x, 39, self.word_size)
            self.sig_1 = lambda x: rotr(x, 14, self.word_size) ^ rotr(x, 18, self.word_size) ^ rotr(x, 41, self.word_size)
        self.ch = lambda x, y, z: (x & y) ^ (~x & z)
        self.maj = lambda x, y, z: (x & y) ^ (x & z) ^ (y & z)

    def __hash__(self) -> int:
        return hash(str(self))

    def __eq__(self, other) -> bool:
        return self.__out_len == other.__out_len

    def __repr__(self) -> str:
        return f'SHA2_{self.__out_len}'

    def __str__(self) -> str:
        return f'SHA2_{self.__out_len}'

    def __lt__(self, other) -> bool:
        return self.__out_len < other.__out_len

    def __le__(self, other) -> bool:
        return self.__out_len <= other.__out_len


CONST_DICT = {
    224: SHA2Constant(224),
    256: SHA2Constant(256),
    384: SHA2Constant(384),
    512: SHA2Constant(512)
}


def sha_2_f(Mi, IV, domain):
    theta0 = domain.theta_0
    theta1 = domain.theta_1
    sig0 = domain.sig_0
    sig1 = domain.sig_1
    ch = domain.ch
    maj = domain.maj
    mod = domain.addition_mod

    Ws = chunk_string(Mi, domain.word_size)
    for t in range(len(Ws), domain.rounds):
        w0 = int(Ws[t - 16], 2)
        w1 = int(Ws[t - 15], 2)
        w2 = int(Ws[t - 7], 2)
        w3 = int(Ws[t - 2], 2)
        w = (w0 + theta0(w1) + w2 + theta1(w3)) % mod
        Ws.append(bin(w)[2:])

    a, b, c, d, e, f, g, h = IV
    for t, k in enumerate(domain.k):
        w = int(Ws[t], 2)
        temp1 = (h + sig1(e) + ch(e, f, g) + k + w) % mod
        temp2 = (sig0(a) + maj(a, b, c)) % mod

        h = g
        g = f
        f = e
        e = (d + temp1) % mod
        d = c
        c = b
        b = a
        a = (temp1 + temp2) % mod

    h0, h1, h2, h3, h4, h5, h6, h7 = IV
    h0 = (h0 + a) % mod
    h1 = (h1 + b) % mod
    h2 = (h2 + c) % mod
    h3 = (h3 + d) % mod
    h4 = (h4 + e) % mod
    h5 = (h5 + f) % mod
    h6 = (h6 + g) % mod
    h7 = (h7 + h) % mod
    Hi = [h0, h1, h2, h3, h4, h5, h6, h7]
    return Hi


def sha_2_pad(message: bytes, domain: SHA2Constant) -> str:
    bits = ''.join(bin(byte)[2:].zfill(8) for byte in message)
    L = len(bits)
    K = (domain.padding_mod - domain.padding_int_bits - 1 - L) % domain.padding_mod
    message = f'{"".join([str(v) for v in bits])}1{"0" * K}{bin(L)[2:domain.padding_int_bits + 3][:domain.padding_int_bits].zfill(domain.padding_int_bits)}'
    return L, K, message


def sha2(message: bytes, out_len: int = 256, verbose: bool = False) -> int:
    """
    Returns the SHA-2 hash of the message.

    :param message: The message to hash.
    :param out_len: The output length level of the hash. Can be 224, 256, 384, or 512.
    :return: The hash of the message.
    """
    domain = CONST_DICT[out_len]
    _, _, message = sha_2_pad(message, domain)
    Mis = chunk_string(message, domain.chunk_size)
    Hi = domain.iv
    for i, Mi in enumerate(Mis):
        Hi = sha_2_f(Mi, Hi, domain)
        if verbose:
            print(f'\t\tH_{i} -> {hex(int("".join([bin(num)[2:].zfill(domain.word_size) for num in Hi]), 2))}')
    if verbose:
        print(f'\t\tH_N -> {hex(int("".join([bin(num)[2:].zfill(domain.word_size) for num in Hi]), 2))}')
    return int(''.join([bin(num)[2:].zfill(domain.word_size) for num in Hi[:domain.hi_len]]), 2)


def sha224(message: bytes) -> int:
    """
    Returns the SHA-224 hash of the message.

    :param message: The message to hash.
    :return: The hash of the message.
    """
    return sha2(message, 224)


def sha256(message: bytes) -> int:
    """
    Returns the SHA-256 hash of the message.

    :param message: The message to hash.
    :return: The hash of the message.
    """
    return sha2(message, 256)


def sha384(message: bytes) -> int:
    """
    Returns the SHA-384 hash of the message.

    :param message: The message to hash.
    :return: The hash of the message.
    """
    return sha2(message, 384)


def sha512(message: bytes) -> int:
    """
    Returns the SHA-512 hash of the message.

    :param message: The message to hash.
    :return: The hash of the message.
    """
    return sha2(message, 512)


def main():
    from hashlib import sha224, sha256, sha384, sha512
    light_red = '\033[91m'
    light_green = '\033[92m'
    light_yellow = '\033[93m'
    white = '\033[0m'

    test_vector_all = [(224, sha224), (256, sha256), (384, sha384), (512, sha512)]
    test_vector = test_vector_all
    for message in ['The quick brown fox jumps over the lazy dog', 'Some other dumb sentence that I made up thats really long because I want multiple runs in the function just to make sure that it works well', 'abc', '']:
        print(f'{light_yellow}Message: `{message}`{white}')
        for out_len, test_func in test_vector:
            print(f'\tSHA 2 {out_len}:')
            inp = message.encode()
            raw_actual = hex(sha2(inp, out_len))[2:]
            raw_expected = test_func(inp).digest().hex()
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
