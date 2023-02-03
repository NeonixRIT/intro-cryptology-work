from shift_cipher import ShiftCipher
from substitution_cipher import SubCipher
from permutation_cipher import PermCipher
from transpose_cipher import TransCipher
from affine_cipher import AffineCipher
from hill_cipher import HillCipher

from bbs_cipher import BBSCipher
from trivium_cipher import TriviumCipher
from rc4_cipher import RC4

from time import perf_counter

INDEX_TO_ALPHA = {index: chr(ascii_num) for index, ascii_num in enumerate(range(65, 65 + 26))}
ALPHA_TO_INDEX = {chr(ascii_num): index for index, ascii_num in enumerate(range(65, 65 + 26))}


def time_cipher(cipher, get_key, *get_key_args):
    name = type(cipher).__name__
    start = perf_counter()
    if get_key and get_key_args is not None:
        print(f'{name} Key:'.ljust(25), cipher.get_key(*get_key_args))
    else:
        print(f'{name} Cipher:'.ljust(25), cipher.encrypt())
        print(f'{name} Plain:'.ljust(25), cipher.decrypt())
    stop = perf_counter()
    print(f'Execution time: {round(stop - start, 4)} seconds')
    print()


def main():
    c1 = ShiftCipher(plain_text='HELLOWORLD', key=3)
    time_cipher(c1, False)

    sub_key = {
        'A': 'Z', 'B': 'Y', 'C': 'X',
        'D': 'W', 'E': 'V', 'F': 'U',
        'G': 'T', 'H': 'S', 'I': 'R',
        'J': 'Q', 'K': 'P', 'L': 'O',
        'M': 'N', 'N': 'M', 'O': 'L',
        'P': 'K', 'Q': 'J', 'R': 'I',
        'S': 'H', 'T': 'G', 'U': 'F',
        'V': 'E', 'W': 'D', 'X': 'C',
        'Y': 'B', 'Z': 'A',
    }
    c2 = SubCipher(plain_text="HELLO THIS IS A TEST", key=sub_key)
    time_cipher(c2, False)

    c3 = PermCipher(plain_text='substitutionciphersaretooeasytobreak'.upper(), key={1: 3, 2: 4, 3: 2, 4: 1, 5: 5})
    time_cipher(c3, False)

    c4 = TransCipher(plain_text='substitutionciphersaretooeasytobreak'.upper(), key=5)
    time_cipher(c4, False)

    c5 = AffineCipher(plain_text='alice'.upper(), key=(3, 6))
    time_cipher(c5, False)

    c6 = HillCipher(plain_text='help'.upper(), key=((3, 7), (5, 12)))
    time_cipher(c6, False)

    # # Known Plaintext Attack
    c7 = HillCipher(plain_text='help'.upper(), cipher_text='xfib'.upper())
    time_cipher(c7, True, 2)

    c8 = BBSCipher(plain_text='SOMETHING', seed=('101010', 49 ** 13))
    time_cipher(c8, False)

    # Key/Nonce is generated to be psuedorandom bits of set length
    c9 = TriviumCipher(plain_text='s p a c e s')
    time_cipher(c9, False)

    # Seed is generated to be a psuedorandom length with psuedorandom bits
    c10 = RC4(plain_text='other string')
    time_cipher(c10, False)


if __name__ == '__main__':
    main()
