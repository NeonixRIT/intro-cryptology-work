from os import environ
from random import SystemRandom
from sys import byteorder
from typing import Any

from math import frexp, isinf, isfinite
from sys import maxsize, version_info

"""
Reference: https://github.com/python/cpython

Attempt to fully implement Python's hash() function in Python
"""

# Python hash/config constants
# Supposed to change based on system architechture
# TODO: refactor into object
CUTOFF = 0
SIZEOF_PY_HASH_T = 8 if maxsize.bit_length() > 32 else 4
HASH_INF = 314159
HASH_MULTIPLIER = 1000003  # 0xf4243 # 1000003
HASH_IMAG = HASH_MULTIPLIER
HASH_BITS = 61 if SIZEOF_PY_HASH_T >= 8 else 31
HASH_MODULUS = (1 << HASH_BITS) - 1
HASH_XXPRIME_1 = 11400714785074694791
HASH_XXPRIME_2 = 14029467366897019727
HASH_XXPRIME_5 = 2870177450012600261


# xxHash Function Definitions for hashing Tuples
def HASH_XXROTATE64(x: int) -> int:
    # rotate left 31 bits
    return ((x << 31) | (x >> 33)) & 0xFFFFFFFFFFFFFFFF


def HASH_XXROTATE32(x: int) -> int:
    # rotate left 13 bits
    return ((x << 13) | (x >> 13)) & 0xFFFFFFFF


HASH_XXROTATE = HASH_XXROTATE64 if SIZEOF_PY_HASH_T == 8 else HASH_XXROTATE32

if SIZEOF_PY_HASH_T == 4:
    HASH_XXPRIME_1 = 2654435761
    HASH_XXPRIME_2 = 2246822519
    HASH_XXPRIME_5 = 374761393


# Check if PYTHONHASHSEED is environment variable is set
# If not set: use random seed, if it is: ensure it is a valid integer and use it as seed
HASH_SEED = environ.get('PYTHONHASHSEED', 'random').strip()
if HASH_SEED != 'random':
    if HASH_SEED.isdigit() and (0 <= int(HASH_SEED) <= 4294967295):
        HASH_SEED = int(HASH_SEED)
    else:
        raise RuntimeError('Fatal Python error: config_init_hash_seed: PYTHONHASHSEED must be "random" or an integer in range [0; 4294967295]')


# Function used to generate hash secret based on seed
def lcg_urandom(x0, size) -> bytes:
    buffer = []
    x = x0 & 0xFFFFFFFF
    for _ in range(size):
        x = (x * 214013 + 2531011) & 0xFFFFFFFF
        buffer.append((x >> 16) & 0xFF)
    return bytes(buffer)


# true random function
def pyurandom(size: int) -> bytes:
    return SystemRandom().randbytes(size)


# Set the hash secret based on seed
U = pyurandom(24) if HASH_SEED == 'random' else lcg_urandom(HASH_SEED, 24)


# Helper functions for hashing
def _u64tos(x: int):
    """
    Convert to signed 64-bit integer
    """
    return (x + (1 << 63)) % (1 << 64) - (1 << 63)


def _le64toh(x: int):
    """
    Convert little-endian 64-bit integer to host byte order
    """
    if byteorder == 'little':
        return x
    return int.from_bytes(x.to_bytes(8, 'little'), 'big')


def rotl64(x, b):
    return ((x << b) & 0xFFFFFFFFFFFFFFFF) | (x >> (64 - b))


def rotr64(x, b):
    return (x >> b) | ((x << (64 - b)) & 0xFFFFFFFFFFFFFFFF)


# SipHash Functions
def half_round(a, b, c, d, s, t):
    a = (a + b) & 0xFFFFFFFFFFFFFFFF
    c = (c + d) & 0xFFFFFFFFFFFFFFFF
    b = rotl64(b, s) ^ a
    d = rotl64(d, t) ^ c
    a = rotl64(a, 32)
    return a, b, c, d


def single_round(v0, v1, v2, v3):
    v0, v1, v2, v3 = half_round(v0, v1, v2, v3, 13, 16)
    v2, v1, v0, v3 = half_round(v2, v1, v0, v3, 17, 21)
    return v0, v1, v2, v3


def double_round(v0, v1, v2, v3):
    v0, v1, v2, v3 = single_round(v0, v1, v2, v3)
    return single_round(v0, v1, v2, v3)


def siphash13(k0: int, k1: int, src: bytes) -> int:
    src_sz = len(src) & 0xFF
    b = src_sz << 56

    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573

    # Process the message in 8-byte chunks
    # convert each 8 byte chunk of the src to the endianness of the host machine
    while src_sz >= 8:
        d = src[:8]
        mi = _le64toh(int.from_bytes(d, 'little'))
        v3 ^= mi
        v0, v1, v2, v3 = single_round(v0, v1, v2, v3)
        v0 ^= mi
        src = src[8:]
        src_sz -= len(d)

    pt = [0] * 8
    for i in range(src_sz - 1, -1, -1):
        pt[i] = src[i]
    t = _le64toh(int.from_bytes(bytes(pt), 'little'))
    b |= t

    # compression
    v3 ^= b
    v0, v1, v2, v3 = single_round(v0, v1, v2, v3)
    v0 ^= b

    # finalization
    v2 ^= 0xFF
    v0, v1, v2, v3 = single_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = single_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = single_round(v0, v1, v2, v3)

    return (v0 ^ v1) ^ (v2 ^ v3)


def siphash24(k0: int, k1: int, src: bytes) -> int:
    src_sz = len(src)
    b = src_sz << 56
    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573

    # Process the message in 8-byte chunks
    # convert each 8 byte chunk of the src to the endianness of the host machine
    while src_sz >= 8:
        d = src[:8]
        mi = _le64toh(int.from_bytes(d, 'little'))
        v3 ^= mi
        v0, v1, v2, v3 = double_round(v0, v1, v2, v3)
        v0 ^= mi
        src = src[8:]
        src_sz -= len(d)

    pt = [0] * 8
    for i in range(src_sz - 1, -1, -1):
        pt[i] = src[i]
    t = int.from_bytes(bytes(pt), 'little')
    b |= _le64toh(t)

    # compression
    v3 ^= b
    v0, v1, v2, v3 = double_round(v0, v1, v2, v3)
    v0 ^= b

    # finalization
    v2 ^= 0xFF
    v0, v1, v2, v3 = double_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = double_round(v0, v1, v2, v3)

    return (v0 ^ v1) ^ (v2 ^ v3)


# Hash functions for different types
def python_hash_integer(data: int) -> int:
    """
    Python's hash function for integers.

    0x1fffffffffffffff is the hex (base16) representation of 2 ** 61 - 1
    """
    if data < 0:
        return -((-data) % 0x1FFFFFFFFFFFFFFF)
    return _u64tos(data % 0x1FFFFFFFFFFFFFFF)


def python_hash_boolean(data: bool) -> int:
    return python_hash_integer(int(data))


def djbx33a(data: bytes, suffix: bytes) -> int:
    """
    Hash function used for small strings in Python.
    """
    # ((h << 5) + h) + byte == h * 33 + byte
    h = 5381
    for byte in data:
        h = ((h << 5) + h) + byte
    h ^= len(data)
    h ^= int.from_bytes(suffix, 'little')
    return h


def python_hash_pointer(data: object):
    return _u64tos(rotr64(id(data), 4))


def python_hash_bytes(data: bytes):
    # TODO: change alg based on a config
    if len(data) == 0:
        return 0
    if len(data) < CUTOFF:  # use separate function for small strings
        return _u64tos(djbx33a(data, U[16:]))
    else:
        return _u64tos(siphash13(_le64toh(int.from_bytes(U[:8], 'little')), _le64toh(int.from_bytes(U[8:16], 'little')), data))


def python_hash_string(data: str):
    # turn string into a list of ascii values (bytes)
    data = data.encode()
    return python_hash_bytes(data)


def python_hash_double(v: float):
    if not isfinite(v):
        if isinf(v):
            return HASH_INF if v > 0 else -HASH_INF
        else:
            return python_hash_pointer(id(v))

    m, e = frexp(v)

    sign = 1
    if m < 0:
        sign = -1
        m = -m

    x = 0
    while m:
        x = ((x << 28) & 0x1FFFFFFFFFFFFFFF) | x >> (61 - 28)
        m *= 268435456.0
        e -= 28
        y = int(m)
        m -= y
        x += y
        if x >= 0x1FFFFFFFFFFFFFFF:
            x -= 0x1FFFFFFFFFFFFFFF

    e = e % 61 if e >= 0 else 61 - 1 - ((-1 - e) % 61)
    x = ((x << e) & 0x1FFFFFFFFFFFFFFF) | x >> (61 - e)

    return x * sign


def python_hash_tuple(data: tuple) -> int:
    """
    Python's hash function for tuples.

    Version of xxHash on each element of the tuple and combine the results.
    """
    data_len = len(data)

    acc = HASH_XXPRIME_5
    for i in range(data_len):
        lane = python_hash(data[i])
        if lane == -1:
            return -1
        acc = (acc + (lane * HASH_XXPRIME_2)) & 0xFFFFFFFFFFFFFFFF
        acc = HASH_XXROTATE(acc)
        acc = (acc * HASH_XXPRIME_1) & 0xFFFFFFFFFFFFFFFF

    acc = (acc + (data_len ^ HASH_XXPRIME_5 ^ 3527539)) & 0xFFFFFFFFFFFFFFFF

    if acc == -1:
        return 1546275796
    return _u64tos(acc)


def python_hash_range(data: range) -> int:
    length = len(data)
    start = data.start if length > 0 else None
    step = data.step if length > 1 else None
    t = (length, start, step)
    return python_hash_tuple(t)
    # if length == 0:
    # else:
    #     t = (length, data.start, None)
    #     if length > 1:
    #         t = (length, data.start, data.step)
    #     else:
    #         t = (length, data.start, None)
    #     return python_hash_tuple(t)
    # start = data.start if length > 0 else None
    # step = data.step if length > 0 else None


def python_hash_slice_part(com: int | None, acc: int):
    lane = python_hash_integer(com) if com is not None else python_hash_none(com)
    if lane == -1:
        return -1
    acc = (acc + ((lane * HASH_XXPRIME_2) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
    acc = HASH_XXROTATE(acc)
    acc = (acc * HASH_XXPRIME_1) & 0xFFFFFFFFFFFFFFFF
    return acc


def python_hash_slice(data: slice) -> int:
    '''
    TODO: FIX calc for slices:
        slice(None, 0, None)
        slice(0, 14, None)
        slice(0, 16, None)
        slice(0, 19, 1)
        slice(0, 19, 4)
    '''
    if version_info < (3, 12, 0):
        raise NotImplementedError('hashing slice objects is not supported in Python versions < 3.12.0')
    acc = HASH_XXPRIME_5
    acc = python_hash_slice_part(data.start, acc)
    acc = python_hash_slice_part(data.stop, acc)
    acc = python_hash_slice_part(data.step, acc)
    if acc == -1:
        return 1546275796
    return _u64tos(acc)


def python_hash_memoryview(data: memoryview) -> int:
    if not data.readonly:
        raise ValueError('cannot hash writable memoryview object')

    if data.format != 'B' and data.format != 'b' and data.format != 'c':
        raise ValueError("memoryview: hashing is restricted to formats 'B', 'b', or 'c'")

    if data.obj is not None and python_hash(data.obj) == -1:
        return -1

    return python_hash_bytes(data.tobytes())


def python_hash_none(data: None) -> int:
    if version_info < (3, 12, 0):
        return _u64tos(python_hash_pointer(data))
    return _u64tos(0xFCA86420)


HASH_TYPES_AND_FUNCS = {
    int: python_hash_integer,
    bool: python_hash_boolean,
    bytes: python_hash_bytes,
    str: python_hash_string,
    float: python_hash_double,
    tuple: python_hash_tuple,
    range: python_hash_range,
    slice: python_hash_slice,
    memoryview: python_hash_memoryview,
}


# Main hash function
def python_hash(data: Any) -> int:
    """
    main function to hash data.

    does not respect object's __hash__ functions

    Does not currently handle slice, range, or memoryview objects
        - range hash function creates a tuple of 3 (length, start, step) with logic setting each to None accordingly
        - slice hash function similar to tuple uses modified xxHash on start, stop, and step
        - memoryview hash function can only hash readonly memoryviews in formats B, b, or c, else, hashes buffer (bytes)
    """
    if data is None:
        return python_hash_none(data)

    # unhashable types raise error
    if isinstance(data, (list, dict, set, bytearray)) or getattr(data, '__hash__', None) is None:
        raise TypeError(f'unhashable type: {type(data).__name__}')

    hash_types_and_funcs = HASH_TYPES_AND_FUNCS
    hash_value = 0
    if type(data) in hash_types_and_funcs:
        hash_value = hash_types_and_funcs[type(data)](data)
    elif isinstance(data, object):
        hash_value = python_hash_pointer(data)
    return hash_value if hash_value != -1 else -2


# Compare builtin hash with this implementation of various types to ensure same hashes are computed
def main():
    """
    Run with setting the PYTHONHASHSEED environment variable so computed and python hashes match
    e.g.
        PYTHONHASHSEED=100 python pyhash.py
    """

    def random_string(length: int) -> str:
        return ''.join(chr(SystemRandom().randrange(97, 123)) for _ in range(length))

    class TestObject:
        def __init__(self, name):
            self.name = name
        def __str__(self):
            return f'TestObject({self.name=}, ptr={id(self)})'

    sys_rand = SystemRandom()
    rand_string = random_string(20)
    rand_bytes = random_string(20).encode()
    rand_int = sys_rand.randint(0, 1000000000)
    rand_double = sys_rand.random()
    rand_obj = TestObject(rand_string)
    rand_tup = tuple([sys_rand.randint(0, 11) for _ in range(sys_rand.randint(0, 11))])
    rand_range1 = range(sys_rand.randint(0, 11))
    rand_range2 = range(sys_rand.randint(0, 11), sys_rand.randint(11, 22))
    rand_range3 = range(sys_rand.randint(0, 11), sys_rand.randint(11, 22), sys_rand.randint(1, 5))
    none = None
    bool_t = True
    bool_f = False
    rand_slice1 = slice(sys_rand.randint(0, 11))
    rand_slice2 = slice(sys_rand.randint(0, 11), sys_rand.randint(11, 22))
    rand_slice3 = slice(sys_rand.randint(0, 11), sys_rand.randint(11, 22), sys_rand.randint(1, 5))
    norm_slice1 = slice(None, None, None),
    norm_slice2 = slice(0, None, None),
    norm_slice3 = slice(None, 0, None),
    norm_slice4 = slice(None, None, 0),
    rand_memoryview = memoryview(random_string(20).encode())

    things_to_hash = [
        rand_string, rand_bytes, rand_int,
        rand_double, rand_tup, rand_obj,
        rand_range1, rand_range2, rand_range3,
        none, bool_t, bool_f,
        rand_slice1, rand_slice2, rand_slice3,
        norm_slice1, norm_slice2, norm_slice3,
        norm_slice4, rand_memoryview
    ]

    print(things_to_hash, '\n')
    for obj in things_to_hash:
        res1 = python_hash(obj)
        res2 = hash(obj)

        print(f'Object ({type(obj).__name__})'.ljust(21), f': {obj}')
        print(f'\tComputed hash : {res1}')
        print(f'\tPython hash   : {res2}')
        print()
        assert res1 == res2, f'Hashes do not match for {obj=}'


if __name__ == '__main__':
    main()
