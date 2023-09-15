from os import urandom
from sys import byteorder

from key import Key
from stream_cipher import StreamCipher, StreamGenerator

from utils import shift_right, string_to_bits


def trivium_cycle(block_1: list[int], block_2: list[int], block_3: list[int]) -> None:
    b1_o = (block_1[-1] + block_1[65]) % 2
    b2_o = (block_2[-1] + block_2[68]) % 2
    b3_o = (block_3[-1] + block_3[67]) % 2

    b1_i = (block_1[68] + (b3_o + (block_3[108] & block_3[109]))) % 2
    b2_i = (block_2[77] + (block_1[90] & block_1[91])) % 2
    b3_i = (block_3[88] + (block_2[81] & block_2[82])) % 2

    del block_1[-1]
    del block_2[-1]
    del block_3[-1]

    block_1.append(b1_i)
    block_2.append(b2_i)
    block_3.append(b3_i)

    block_1 = shift_right(block_1, 1)
    block_2 = shift_right(block_2, 1)
    block_3 = shift_right(block_3, 1)

    zi = (b1_o + b2_o + b3_o) % 2
    return block_1, block_2, block_3, zi


class TriviumKey(Key):
    def __init__(self, seed: str | list = None, nonce: str | list = None, is_string: bool = False, is_binary: bool = False):
        self.is_string = is_string
        self.is_binary = is_binary

        friendly_name = None
        seed = [int(bit) for bit in bin(int.from_bytes(urandom(80 // 8), byteorder=byteorder))[2:].zfill(80)] if seed is None else seed
        nonce = [int(bit) for bit in bin(int.from_bytes(urandom(80 // 8), byteorder=byteorder))[2:].zfill(80)] if nonce is None else nonce
        if is_string:
            friendly_name = f'{seed} {nonce}'
            seed = string_to_bits(seed)
        elif is_binary:
            tmp_key_val = ''.join([str(bit) for bit in seed])
            tmp_nonce_val = ''.join([str(bit) for bit in nonce])
            friendly_name = f'{hex(int(tmp_key_val, 2))[2:]} {hex(int(tmp_nonce_val, 2))[2:]}'

        self.seed = seed
        self.nonce = nonce

        super().__init__(seed, friendly_name)


def trivium_ksg(key: TriviumKey, length=1000):
    if len(key.seed) != 80 or len(key.nonce) != 80:
        raise ValueError("The key and nonce must be 80 bits long.")
    length += (4 * 288)  # add warmup
    block_1 = [int(key.seed[i]) if i < len(key.seed) else 0 for i in range(93)]
    block_2 = [int(key.nonce[i]) if i < len(key.nonce) else 0 for i in range(84)]
    block_3 = [1 if i > 107 else 0 for i in range(111)]
    for i in range(length):
        block_1, block_2, block_3, zi = trivium_cycle(block_1, block_2, block_3)
        if i > 4 * 288:
            yield zi


class TriviumKSG(StreamGenerator):
    def __init__(self, key: TriviumKey):
        super().__init__(key)

    def __call__(self, length):
        return trivium_ksg(self.key, length)


class TriviumCipher(StreamCipher):
    def __init__(self, plain_text: str = None, cipher_text: str = None, key: TriviumKey = None):
        key = TriviumKey(is_binary=True) if key is None else key
        super().__init__(plain_text, cipher_text, TriviumKSG(key))
