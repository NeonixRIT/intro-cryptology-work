'''
DEPRECATED
'''
from key import Key
from stream_cipher import StreamCipher

from shift_cipher import ShiftCipher
from substitution_cipher import SubCipher
from permutation_cipher import PermCipher
from transpose_cipher import TransCipher
from affine_cipher import AffineCipher
from hill_cipher import HillCipher

from bbs_cipher import BBSCipher, BBSKey
from trivium_cipher import TriviumCipher, TriviumKey
from rc4_cipher import RC4, RC4Key


from utils import feistel_system, example_f, example_ksa, chunk_string

from time import perf_counter

INDEX_TO_ALPHA = {index: chr(ascii_num) for index, ascii_num in enumerate(range(65, 65 + 26))}
ALPHA_TO_INDEX = {chr(ascii_num): index for index, ascii_num in enumerate(range(65, 65 + 26))}


def time_cipher(cipher, get_key, *get_key_args):
    name = type(cipher).__name__

    start = perf_counter()
    key = cipher.get_key(*get_key_args) if get_key else cipher.key
    cipher_text = cipher.encrypt()
    plain_text = cipher.decrypt()
    stop = perf_counter()

    try:
        cipher_text = hex(int(cipher_text, 2))[2:]
    except (TypeError, ValueError):
        pass

    if len(str(key)) > 32:
        key = str(key)[:32] + '...'

    print(f'{name} Key:'.ljust(25), key)
    if not get_key:
        print(f'{name} Cipher:'.ljust(25), cipher_text)
        print(f'{name} Plain:'.ljust(25), plain_text)
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

    t = 'svunhnvpuhaptlmvynvaaluhwylalyuhabyhslcluaaoyldaolzlhzvuzvbavmihshujlpuhshukdolylzbttlyzjhushzakljhklzhukdpualyzhspmlaptlayvbislpziyldpun'.upper()
    ShiftCipher(cipher_text=t).get_key()


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

    c8 = BBSCipher(plain_text='SOMETHING', key=BBSKey(49 ** 13, '101010'))
    time_cipher(c8, False)

    # Key/Nonce is generated to be psuedorandom bits of set length
    c9 = TriviumCipher(plain_text='s p a c e s')
    time_cipher(c9, False)

    # Seed is generated to be a psuedorandom length with psuedorandom bits
    c10 = RC4(plain_text='other string')
    time_cipher(c10, False)

    # Test RC4 with wikipedia example
    c11 = RC4(plain_text='pedia', key=RC4Key('Wiki', is_string=True))
    time_cipher(c11, False)

    # Test Feistel System
    rounds = 1000000
    start = perf_counter()
    result = feistel_system('10010001', example_f, example_ksa('1010', rounds + 1), 8, rounds, is_bits=True)
    stop = perf_counter()
    print('Feistel System Result:', result)
    print(f'Execution time: {round(stop - start, 4)} seconds')
    print()

    # Test DES. First Example from https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
    # c12 = DESCipher(plaintext='Your lips are smoother than vaseline', key=DESKey(''.join([bin(int(val, 16))[2:].zfill(8) for val in '0E 32 92 32 EA 6D 0D 73'.split()]), is_string=False))
    # time_cipher(c12, False)

    # c13 = DESCipher(plaintext='ADESTEST', key=DESKey('SOMEKEYV', is_string=True))
    # time_cipher(c13, False)


# if __name__ == '__main__':
#     main()
