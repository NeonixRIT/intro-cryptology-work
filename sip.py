from utils import rotl, generate_random_bits, chunk_string, bits_to_bytes, little_endian_to_int, int_to_little_endian_bytes


def sip_round(v0, v1, v2, v3, bit_limit: int = 64):
    andy = 2 ** bit_limit - 1

    v0 = (v0 + v1) & andy
    v2 = (v2 + v3) & andy
    v1 = rotl(v1, 13, bit_limit) ^ v0
    v3 = rotl(v3, 16, bit_limit) ^ v2
    v0 = rotl(v0, 32, bit_limit)

    v2 = (v2 + v1) & andy
    v0 = (v0 + v3) & andy
    v1 = rotl(v1, 17, bit_limit) ^ v2
    v3 = rotl(v3, 21, bit_limit) ^ v0
    v2 = rotl(v2, 32, bit_limit)
    return v0, v1, v2, v3


def doublesiprounds(v, m):
    v0, v1, v2, v3 = v
    v3 ^= m
    v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
    v0 ^= m
    return v0, v1, v2, v3


def pad_64_blocks(input_bytes: bytes) -> bytes:
    input_len = len(input_bytes)
    padding_len = 8 - 1 - (input_len % 8)
    if padding_len == 8:
        padding_len = 0
    padded_bytes = input_bytes + (b'\x00' * padding_len)
    final_byte = input_len & 0xff
    padded_bytes += bytes([final_byte])
    return padded_bytes


def initialize_state(key: bytes) -> tuple:
    k0 = little_endian_to_int(key[:8])
    k1 = little_endian_to_int(key[8:])
    v0 = k0 ^ 0x736f6d6570736575
    v1 = k1 ^ 0x646f72616e646f6d
    v2 = k0 ^ 0x6c7967656e657261
    v3 = k1 ^ 0x7465646279746573
    return v0, v1, v2, v3


def siphashcdo(c: int, d: int, o: int, message: bytes, k: bytes) -> int:
    if o % 64 != 0:
        raise ValueError('Output length must be a multiple of 64 bits')

    His = []
    hashes = o // 64
    keys = [k]
    if hashes > 1:
        primes_1024 = [117649480502377461365207627149707469174936080651862992874628987077395027668294526513237280061790225207577518599478760971419509481158740434995649146175959777119592353403343160291322080252317378394699500081055870395018512357208494573801724461883871028401533033511329923913982414239850987666610523847715282526767, 168290070835484540629579559707915510377330207883288564603989658794596105932663650324122981821373074870795312591120573447784576954706757848907794362056990604184892742035520145432093708489940692845345729054387762082198570049393653026519768348986007669228578419681148770215200057635184313515515487874026727826317, 137204910402061495523680237503857971715777708702553006901693921811338637722240170575831774409282607636429110580291128745123691030670020974668239856662158111773461238756200536746922129017662658262578905338272418329855534520128218009514925225327400103012107136939741551563196249634740309696091983761265883057697, 99956092577960678648411945419788684670272929077356831421344201309275012049891840433059056958801097418474135019812868163525099754229788402809967721441552028403660903857522546293179518208809258934901416635846544342299087483503809462121230759077196309068135652284226101988061311310654336939191763968677880368927]
        primes_bin = ''.join([bin(prime)[2:] for prime in primes_1024])
        key_bin = bin(little_endian_to_int(k) ** hashes)[2:]
        if len(key_bin) < o * 2 + 256:
            key_bin = key_bin + primes_bin[:o * 2 + 256 - len(key_bin)]
        ksa = generate_random_bits(o * 2, key_bin)
        keys = chunk_string(next(ksa), 128)
        keys = [int_to_little_endian_bytes(int(key, 2)) for key in keys]


    for i in range(hashes):
        v0, v1, v2, v3 = initialize_state(keys[i])
        padded_message = pad_64_blocks(message)
        blocks = chunk_string(padded_message, 8)
        for chunk in blocks:
            m = little_endian_to_int(chunk)
            v3 ^= m
            for _ in range(c):
                v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
            v0 ^= m

        v2 ^= 0xff
        for _ in range(d):
            v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)

        His.append(v0 ^ v1 ^ v2 ^ v3)

    H = His[0]
    for hi in His[1:]:
        H = (H << 64) | hi

    return H


class SIPCDO:
    def __init__(self, c: int = 2, d: int = 4, k=None, out_len: int = 64):
        self.c = c
        self.d = d
        self.o = out_len
        self.__k = k if k else b''.join(bits_to_bytes(next(generate_random_bits(128))))

    @property
    def __name__(self):
        return f'SIP-{self.c}{self.d}-{self.o}'

    def __call__(self, message: bytes) -> int:
        return siphashcdo(self.c, self.d, self.o, message, self.__k)


sip13 = SIPCDO(1, 3, out_len=64)
sip24 = SIPCDO(2, 4, out_len=64)
sip35 = SIPCDO(3, 5, out_len=64)
sip24_128 = SIPCDO(2, 4, out_len=128)
sip24_256 = SIPCDO(2, 4, out_len=256)
sip24_512 = SIPCDO(2, 4, out_len=512)
sip24_1024 = SIPCDO(2, 4, out_len=1024)
sip24_2048 = SIPCDO(2, 4, out_len=2048)
sip24_4096 = SIPCDO(2, 4, out_len=4096)
