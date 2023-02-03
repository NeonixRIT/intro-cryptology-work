import numpy as np

from stream_cipher import StreamCipher, StreamGenerator


def bbs_ksg(seed: tuple[str | int, int], length=1000):
    if len(seed) != 2:
        raise ValueError("The seed must have 2 values.")

    key = 0
    if isinstance(seed[0], str):
        key = int(seed[0], 2)
    elif isinstance(seed[0], int):
        key = seed[0]
    else:
        raise ValueError("The key must be a string of bits or an integer.")

    n = seed[1]
    xi = key
    for _ in range(length):
        xi = (xi ** 2) % n
        yield xi % 2


class BBSKSG(StreamGenerator):
    def __init__(self, seed):
        super().__init__(seed)

    def __call__(self, length):
        return bbs_ksg(self.seed, length)


class BBSCipher(StreamCipher):
    def __init__(self, plain_text: str = None, cipher_text: str = None, seed: tuple[str | int, int] = None):
        seed = tuple([''.join([np.random.randint(5, 40) % 2 for _ in range(6)]), np.random.randint(5, 129384)]) if seed is None else seed
        super().__init__(plain_text, cipher_text, BBSKSG(seed))


def main():
    ksg = BBSKSG(('101000', 307 * 491))
    for out in ksg(42):
        print(out, end='')


if __name__ == '__main__':
    main()
