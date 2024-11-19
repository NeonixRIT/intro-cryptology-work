from itertools import batched
from keccak import prng_shake128
from random import SystemRandom

BLOCK_SIZE = 64
ANDY = 2**BLOCK_SIZE - 1


def rotl(num: int, bits: int) -> int:
    return ((num & ANDY) << bits) | (num >> (BLOCK_SIZE - bits))


def int_to_bytes(number: int, size: int = None, endian: str = 'little', signed=False) -> bytes:
    if size is None:
        size = (number.bit_length() + 7) // 8
    return number.to_bytes(size, endian, signed=signed)


def bytes_to_int(b: bytes, endian: str = 'little', signed=False) -> int:
    return int.from_bytes(b, endian, signed=signed)


def half_round(a, b, c, d, s, t):
    a = (a + b) & ANDY
    c = (c + d) & ANDY
    b = rotl(b, s) ^ a
    d = rotl(d, t) ^ c
    a = rotl(a, 32)
    return a, b, c, d


def sip_round(v0, v1, v2, v3):
    """
    Perform a single round of SipHash

    ARX - add, rotate, xor
    rotl - rotate integer left
    rotl(value, how many bits to rotate: int)
    """
    v0, v1, v2, v3 = half_round(v0, v1, v2, v3, 13, 16)
    v2, v1, v0, v3 = half_round(v2, v1, v0, v3, 17, 21)
    return v0, v1, v2, v3


def pad_64_blocks(input_bytes: bytes) -> bytes:
    """
    Pad input bytes to a multiple of 64 bits by appending 0s
    the final byte is the length of the input in bits
    """
    input_len = len(input_bytes)
    padding_len = 8 - 1 - (input_len % 8)
    if padding_len == 8:
        padding_len = 0
    padded_bytes = input_bytes + (b'\x00' * padding_len)
    final_byte = input_len & 0xFF
    padded_bytes += bytes([final_byte])
    return padded_bytes


def initialize_state(key: bytes) -> tuple:
    """
    Create intial state for SipHash algorithm
    key - 128 bit key
        k0 - first 64 bits
        k1 - second 64 bits
    initialize 4 vectors by xoring key with constants
    constants defined by hash specification.
    """
    k0 = bytes_to_int(key[:8])  # convert bytes to integer
    k1 = bytes_to_int(key[8:])  # convert bytes to integer
    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573
    return v0, v1, v2, v3


def siphashcd(c: int, d: int, message: bytes, k: bytes) -> int:
    """
    Main function that hashes a message using the SipHash algorithm
    c - number of compression rounds
    d - number of finalization rounds
    message - data to be hashed
    k - key

    Returns the hash as an integer
    minimum output length is 64 bits

    if o > 64 then algorithm is run multiple times with different k values and
    the results are concatenated

    O should be handled by a block operation mode
    """
    v0, v1, v2, v3 = initialize_state(k)  # initial state defined by hash specification
    padded_message = pad_64_blocks(message)  # pad message to multiple of 64 bits
    blocks = batched(padded_message, 8)  # split message into 64 bit chunks
    for chunk in blocks:
        m = bytes_to_int(chunk)  # convert bytes to integer
        v3 ^= m
        for _ in range(c):  # compression rounds
            v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
        v0 ^= m

    v2 ^= 0xFF
    for _ in range(d):  # finalization rounds
        v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
    return (v0 ^ v1 ^ v2 ^ v3) & ANDY


class SIPCDO:
    def __init__(self, c: int = 2, d: int = 4, k=None, out_len: int = 64):
        '''
        c - number of compression rounds
        d - number of finalization rounds
        k - key
        out_len - output length in bits
            - This is currently ignored. As it should be handled by something like a block operation mode
            however, they are generally for functions that can't handle multiple blocks.
            - It is not efficient and the security of the output is dubious if the output is greater than 64 bits
            as we are hashing the same message multiple times with different keys
            - Implementation regardless would be wrapping call in a OperationMode where the input is multiple
            blocks of the same message
        '''
        self.c = c
        self.d = d
        self.o = out_len
        self.__k = k if k else SystemRandom().randbytes(16)

    @property
    def __name__(self):
        return f'SIP-{self.c}{self.d}-{self.o}'

    def __call__(self, message: bytes) -> int:
        return siphashcd(self.c, self.d, message, self.__k)


siphash13 = SIPCDO(1, 3)
siphash24 = SIPCDO(2, 4)
siphash35 = SIPCDO(3, 5)
