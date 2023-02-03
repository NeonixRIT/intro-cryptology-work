import numpy as np

from stream_cipher import StreamCipher, StreamGenerator

from utils import shift_right


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


def trivium_ksg(key, nonce, length=1000):
    if len(key) != 80 or len(nonce) != 80:
        raise ValueError("The key and nonce must be 80 bits long.")
    length += (4 * 288)  # add warmup
    block_1 = [int(key[i]) if i < len(key) else 0 for i in range(93)]
    block_2 = [int(nonce[i]) if i < len(nonce) else 0 for i in range(84)]
    block_3 = [1 if i > 107 else 0 for i in range(111)]
    for i in range(length):
        block_1, block_2, block_3, zi = trivium_cycle(block_1, block_2, block_3)
        if i > 4 * 288:
            yield zi


class TriviumKSG(StreamGenerator):
    def __init__(self, seed, nonce):
        self.nonce = nonce
        super().__init__(seed)

    def __call__(self, length):
        return trivium_ksg(self.seed, self.nonce, length)


class TriviumCipher(StreamCipher):
    def __init__(self, plain_text: str = None, cipher_text: str = None, seed: str | list = None, nonce: str | list = None):
        seed = [np.random.randint(i, (i + 1) ** 3) % 2 for i in range(80)] if seed is None else seed
        nonce = [np.random.randint(i, (i + 1) ** 3) % 2 for i in range(80)] if seed is None else seed
        super().__init__(plain_text, cipher_text, TriviumKSG(seed, nonce))
