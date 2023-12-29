import random

'''
Implementation of SipHash-C-D-O algorithm on a Python level.
Python's default hash runs in C.

@author: Kamron Cole - kjc8084@rit.edu
References:
    1: http://cr.yp.to/siphash/siphash-20120918.pdf
        - Specification document used to implement algorithm
    2: https://github.com/majek/pysiphash/blob/master/siphash/__init__.py
        - Implementation of SipHash-2-4-64 on a Python level
        - Took ideas from this to solve some issues with how python handles integers.

Python's hash function is a variant of the SipHash-C-D-O
Where C, D, and O are parameters that can be adjusted to change the of the algorithm.
Python uses SipHash-2-4-64. This means:
 - 2 `compression` rounds
 - 4 `finalization` rounds
 - Output of 64 bits

Each round is represented by this diagram:
    http://cr.yp.to/siphash/siphash-20120918.pdf, page 5, figure 2.2.

Keep in mind the `bytes` type is just a list of 8 bit integers,
this means each integer can range from 0 to 255, inclusively.
(technically it can also be -127 to 127 but we aren't using negative numbers here)
This is a universal representation for data of any type.

In python, a byte is in the format \xFF where FF can be replaced with any integer 0-255 in base 16.
a byte string is a string of bytes and denoted by a `b` infront of quotes: b''.

The goal here is to first implement SipHash-C-D-O so that implementing
SipHash with any value of C, D, and O is trivial.
'''


def rotl(num: int, bits: int, zfill_len: int):
    '''
    Rotate integer left by specified number of bits.
    This is just like a left shift except the bits that fall off the left side
    are instead appended to the right side.

    num - integer to rotate
    bits - number of bits to rotate left by
    zfill_len - desired result bit size. This is required due to how python handles integers.

    Example rotating 9 left by 2 bits:
    rotl(9, 2, 4)
    Integer 9 is represented by 4 bits:   1001
    Each value is moved left by 2 bits: 100100
    Last two bits are dropped and replaced by the first 2 bits: 0110
    This is achieved by with basic operations like or, and, subtract, and shift.

    Calculations involving `zfill_len` and `andy` are corrections for the fact that python
    integers are not a fixed size.
    '''
    bits %= zfill_len
    if bits == 0:
        return num

    andy = 2 ** (zfill_len - bits) - 1
    return ((num & andy) << bits) | (num >> (zfill_len - bits))


# def rotl(num: int, bits: int):
#     '''
#     Rotate left function if python integers were a fixed size of 32 bits.
#     '''
#     return (num << bits) | (num >> (32 - bits))


def predictable_random_bytes(num_bytes: int, seed: bytes) -> bytes:
    '''
    Generate a sequence of random bytes that are deterministic based on the seed.
    The same seed should produce the same bytes.

    This function is not secure. A secure implementation would use something like a variation of SHA 2 or 3.
    '''
    random.seed(seed)
    result = random.randbytes(num_bytes)
    random.seed(None) # Reset python's random seed
    return result


def chunk_data(data: bytes, chunk_size: int) -> list[bytes]:
    '''
    Split a slicable squence into chunks of specified size.
    '''
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def bytes_to_int(b: bytes) -> int:
    '''
    Convert bytes to integer
    '''
    int_value = 0
    for i in range(len(b)):
        int_value |= (b[i] << (i * 8))
    return int_value


def sip_round(v0, v1, v2, v3, bit_limit: int = 64):
    '''
    Perform a single round of SipHash

    This is an ARX (add, rotate, xor) system.

    `andy` is to correct for how python handles integers.

    13, 16, 32, 17, 21, 31 are fix values defined by hash specification.
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


def pad_64_blocks(data: bytes) -> bytes:
    '''
    Pad bytes of data so that it is a multiple of 8 bytes (64 bits).
    This is done by adding 0s to the end of the data.
    the final byte added is the last 8 bits of the number of bytes of the original.
    '''
    input_len = len(data)
    padding_len = 8 - 1 - (input_len % 8)
    if padding_len == 8:
        padding_len = 0
    padded_bytes = data + (b'\x00' * padding_len) # add padding_len number of 0 bytes to data
    final_byte = input_len & 0xff
    padded_bytes += bytes([final_byte])
    return padded_bytes


def initialize_state(seed: bytes) -> tuple[int, int, int, int]:
    '''
    Create intial state for SipHash algorithm
    seed - 128 bit key
        k0 - first 64 bits
        k1 - second 64 bits
    initialize 4 vectors by xoring seed with constants
    constants are defined by hash specification.
    Each vector is 8 bytes long.
    '''
    k0 = bytes_to_int(seed[:8])
    k1 = bytes_to_int(seed[8:])
    v0 = k0 ^ 0x736f6d6570736575
    v1 = k1 ^ 0x646f72616e646f6d
    v2 = k0 ^ 0x6c7967656e657261
    v3 = k1 ^ 0x7465646279746573
    return v0, v1, v2, v3


def siphashcdo(c: int, d: int, o: int, data: bytes, k: bytes) -> int:
    '''
    Main function that hashes a message using the SipHash algorithm
    c - number of compression rounds
    d - number of finalization rounds
    o - output length in bits
    data - data to be hashed
    k - key (must be 128 bits/16 bytes long)
        - In python this is a truely random number based on a truly random event like system CPU clock timings
        - Cloudflare uses a wall of lava lamps as a source of truly random events to generate random numbers
        - Note that this is distinctly different from Pythons random module

    if o > 64 then algorithm is run multiple times with different k values and
    the hash of each round are concatenated.
    '''
    # Check that output length is a multiple of 64 bits
    if o % 64 != 0:
        raise ValueError(f'Output length of `{o}` is not supported. It must be a multiple of 64 bits.')

    # Check that key/seed length is 128 bits/16 bytes
    if len(k) != 16:
        raise ValueError(f'Key length of `{len(k)}` is not supported. It must be 128 bits/16 bytes long.')

    His = [] # list of resulting hashes to be concatenated
    hashes = o // 64
    seeds = [k]
    # Calculate seeds to be used for each over-arching round.
    # List of round seeds is determined by initial seed meaning that
    # the same initial seed will always produce the same round seeds.
    for i in range(hashes - 1):
        seeds.append(predictable_random_bytes(16, seeds[-1]))

    # Calculate hash for each over-arching round.
    # All this does is hash the same data with a different seed.
    for i in range(hashes):
        v0, v1, v2, v3 = initialize_state(seeds[i]) # initial state defined by hash 4 vectors, 8 bytes long each.
        padded_message = pad_64_blocks(data) # pad message to multiple of 64 bits
        blocks = chunk_data(padded_message, 8) # split message into 64 bit block

        # Process each 64 bit block of data by running each block through `c` number of sip hash rounds
        for block in blocks:
            m = bytes_to_int(block) # convert data block to integer m
            v3 ^= m
            for _ in range(c): # compression rounds
                v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
            v0 ^= m

        v2 ^= 0xff
        for _ in range(d): # finalization rounds
            v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)

        # A 64 bit hash for any data is the xor result of the 4 vectors at the end of rounds.
        His.append(v0 ^ v1 ^ v2 ^ v3)

    # concatenate hashes
    H = His[0]
    for hi in His[1:]:
        H = (H << 64) | hi

    return H


# Global constant SEED value used for all hashes in a single instance of Python.
# Python's hash function operates in the same way.
# Note that this is not a secure way to generate a seed.
SEED = random.randbytes(16)

def sip24_64(data: bytes) -> int:
    '''
    Implementation of SipHash-2-4-64 that Python uses for its hash function.
    '''
    return siphashcdo(2, 4, 64, data, SEED)


def main():
    message_1 = 'Hello World!'
    message_2 = 'Hello World!'
    message_3 = 'Something New!'
    message_4 = 'Something New!'
    print(sip24_64(message_1.encode()))
    print(sip24_64(message_2.encode()))
    print(sip24_64(message_3.encode()))
    print(sip24_64(message_4.encode()))


if __name__ == '__main__':
    main()
