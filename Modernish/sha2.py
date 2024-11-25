def rotr(num, bits, zfill_len):
    return (num >> bits) | (num << zfill_len - bits)


def shr(num, bits):
    return num >> bits


HIS_224 = (0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4)

HIS_256 = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)

KIS_224_256 = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)

HIS_384 = (0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939, 0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4)

HIS_512 = (0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179)

KIS_384_512 = (
    0x428A2F98D728AE22,
    0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC,
    0x3956C25BF348B538,
    0x59F111F1B605D019,
    0x923F82A4AF194F9B,
    0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242,
    0x12835B0145706FBE,
    0x243185BE4EE4B28C,
    0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F,
    0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235,
    0xC19BF174CF692694,
    0xE49B69C19EF14AD2,
    0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5,
    0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483,
    0x5CB0A9DCBD41FBD4,
    0x76F988DA831153B5,
    0x983E5152EE66DFAB,
    0xA831C66D2DB43210,
    0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2,
    0xD5A79147930AA725,
    0x06CA6351E003826F,
    0x142929670A0E6E70,
    0x27B70A8546D22FFC,
    0x2E1B21385C26C926,
    0x4D2C6DFC5AC42AED,
    0x53380D139D95B3DF,
    0x650A73548BAF63DE,
    0x766A0ABB3C77B2A8,
    0x81C2C92E47EDAEE6,
    0x92722C851482353B,
    0xA2BFE8A14CF10364,
    0xA81A664BBC423001,
    0xC24B8B70D0F89791,
    0xC76C51A30654BE30,
    0xD192E819D6EF5218,
    0xD69906245565A910,
    0xF40E35855771202A,
    0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8,
    0x1E376C085141AB53,
    0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63,
    0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373,
    0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC,
    0x78A5636F43172F60,
    0x84C87814A1F0AB72,
    0x8CC702081A6439EC,
    0x90BEFFFA23631E28,
    0xA4506CEBDE82BDE9,
    0xBEF9A3F7B2C67915,
    0xC67178F2E372532B,
    0xCA273ECEEA26619C,
    0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E,
    0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA,
    0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE,
    0x1B710B35131C471B,
    0x28DB77F523047D84,
    0x32CAAB7B40C72493,
    0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6,
    0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC,
    0x6C44198C4A475817,
)


class SHA2Constant:
    def __init__(self, out_len):
        if out_len not in {224, 256, 384, 512}:
            raise ValueError(f'Invalid output length {out_len}: SHA 2 only supports 224, 256, 384, and 512 bit output.')

        self.__out_len = out_len
        self.parent_out = 256 if out_len <= 256 else 512
        self.chunk_size = 512 if out_len <= 256 else 1024
        self.chunk_size_bytes = self.chunk_size // 8
        self.padding_mod = self.chunk_size
        self.padding_int_bits = 64 if out_len <= 256 else 128
        self.word_size = 32 if out_len <= 256 else 64
        self.word_size_bytes = self.word_size // 8
        self.addition_and = 2**self.word_size - 1

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


CONST_DICT = {224: SHA2Constant(224), 256: SHA2Constant(256), 384: SHA2Constant(384), 512: SHA2Constant(512)}


def sha_2_f(Mi: bytes, IV: tuple[int], domain: SHA2Constant):
    theta0 = domain.theta_0
    theta1 = domain.theta_1
    sig0 = domain.sig_0
    sig1 = domain.sig_1
    ch = domain.ch
    maj = domain.maj
    andy = domain.addition_and

    Ws = [int.from_bytes(Mi[i : i + domain.word_size_bytes]) for i in range(0, len(Mi), domain.word_size_bytes)]
    for t in range(len(Ws), domain.rounds):
        w0 = Ws[t - 16]
        w1 = Ws[t - 15]
        w2 = Ws[t - 7]
        w3 = Ws[t - 2]
        w = (w0 + theta0(w1) + w2 + theta1(w3)) & andy
        Ws.append(w)

    a, b, c, d, e, f, g, h = IV
    for t, k in enumerate(domain.k):
        w = Ws[t]
        temp1 = (h + sig1(e) + ch(e, f, g) + k + w) & andy
        temp2 = (sig0(a) + maj(a, b, c)) & andy

        h = g
        g = f
        f = e
        e = (d + temp1) & andy
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & andy

    h0, h1, h2, h3, h4, h5, h6, h7 = IV
    h0 = (h0 + a) & andy
    h1 = (h1 + b) & andy
    h2 = (h2 + c) & andy
    h3 = (h3 + d) & andy
    h4 = (h4 + e) & andy
    h5 = (h5 + f) & andy
    h6 = (h6 + g) & andy
    h7 = (h7 + h) & andy
    Hi = [h0, h1, h2, h3, h4, h5, h6, h7]
    return Hi


def sha_2_pad(message: bytes, domain: SHA2Constant) -> str:
    L = len(message) * 8
    K = (((domain.padding_mod) - (domain.padding_int_bits) - 1 - (L)) % (domain.padding_mod)) // 8
    message = message + b'\x80' + (b'\x00' * K) + (L).to_bytes(domain.padding_int_bits // 8, 'big')
    return L, K, message


def sha2(message: bytes, out_len: int = 256) -> int:
    """
    Returns the SHA-2 hash of the message.

    :param message: The message to hash.
    :param out_len: The output length level of the hash. Can be 224, 256, 384, or 512.
    :return: The hash of the message.
    """
    domain = CONST_DICT[out_len]
    _, _, message = sha_2_pad(message, domain)
    Mis = [message[i : i + domain.chunk_size_bytes] for i in range(0, len(message), domain.chunk_size_bytes)]
    Hi = domain.iv
    for _, Mi in enumerate(Mis):
        Hi = sha_2_f(Mi, Hi, domain)

    H = 0
    for hi in Hi[: domain.hi_len]:
        H = (H << domain.word_size) | hi
    return H


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
