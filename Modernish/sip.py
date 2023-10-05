from utils import rotl, chunk_string, little_endian_to_int
from keccak import prng_shake128


def sip_round(v0, v1, v2, v3, bit_limit: int = 64):
    '''
    Perform a single round of SipHash

    ARX - add, rotate, xor
    rotl - rotate integer left
    rotl(value, how many bits to rotate: int, desired max bit size: int)
    '''
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
    '''
    Perform 2 rounds of SipHash
    Currently not used but can have its uses.
    Was used in example code I found for specific case that didn't apply here.
    '''
    v0, v1, v2, v3 = v
    v3 ^= m
    v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
    v0 ^= m
    return v0, v1, v2, v3


def pad_64_blocks(input_bytes: bytes) -> bytes:
    '''
    Pad input bytes to a multiple of 64 bits by appending 0s
    the final byte is the length of the input in bits
    '''
    input_len = len(input_bytes)
    padding_len = 8 - 1 - (input_len % 8)
    if padding_len == 8:
        padding_len = 0
    padded_bytes = input_bytes + (b'\x00' * padding_len)
    final_byte = input_len & 0xff
    padded_bytes += bytes([final_byte])
    return padded_bytes


def initialize_state(key: bytes) -> tuple:
    '''
    Create intial state for SipHash algorithm
    key - 128 bit key
        k0 - first 64 bits
        k1 - second 64 bits
    initialize 4 vectors by xoring key with constants
    constants defined by hash specification.
    '''
    k0 = little_endian_to_int(key[:8]) # convert bytes to integer
    k1 = little_endian_to_int(key[8:]) # convert bytes to integer
    v0 = k0 ^ 0x736f6d6570736575
    v1 = k1 ^ 0x646f72616e646f6d
    v2 = k0 ^ 0x6c7967656e657261
    v3 = k1 ^ 0x7465646279746573
    return v0, v1, v2, v3


def siphashcdo(c: int, d: int, o: int, message: bytes, k: bytes) -> int:
    '''
    Main function that hashes a message using the SipHash algorithm
    c - number of compression rounds
    d - number of finalization rounds
    o - output length in bits
    message - data to be hashed
    k - key

    Returns the hash as an integer
    minimum output length is 64 bits

    if o > 64 then algorithm is run multiple times with different k values and
    the results are concatenated

    prng_shake128.random_bytes(number of bytes to return, seed)
    '''
    # Check that output length is a multiple of 64 bits
    if o % 64 != 0:
        raise ValueError('Output length must be a multiple of 64 bits')

    His = [] # list of resulting hashes to be concatenated
    hashes = o // 64
    keys = [k]
    # securely calculate subsequent round keys based on the initial key if requested output > 64 bits
    for i in range(hashes - 1):
        keys.append(prng_shake128.random_bytes(16, keys[-1]))


    for i in range(hashes):
        v0, v1, v2, v3 = initialize_state(keys[i]) # initial state defined by hash specification
        padded_message = pad_64_blocks(message) # pad message to multiple of 64 bits
        blocks = chunk_string(padded_message, 8) # split message into 64 bit chunks
        for chunk in blocks:
            m = little_endian_to_int(chunk) # convert bytes to integer
            v3 ^= m
            for _ in range(c): # compression rounds
                v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
            v0 ^= m

        v2 ^= 0xff
        for _ in range(d): # finalization rounds
            v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)

        His.append(v0 ^ v1 ^ v2 ^ v3)

    # concatenate hashes
    H = His[0]
    for hi in His[1:]:
        H = (H << 64) | hi

    return H


class SIPCDO:
    def __init__(self, c: int = 2, d: int = 4, k=None, out_len: int = 64):
        self.c = c
        self.d = d
        self.o = out_len
        self.__k = k if k else prng_shake128.random_bytes(16) # securely generate psuedo random key if none provided

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
