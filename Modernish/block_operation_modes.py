from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from itertools import batched
from multiprocessing import cpu_count
from enum import Enum

from keccak import prng_shake256


def xor_words(a: bytes, b: bytes) -> bytes:
    return bytes([a[i] ^ b[i] for i in range(len(a))])


class OperationMode:
    """
    Each Mode of Operation will have underlying cipher to encrypt/decrypt one block of data.
    Each Mode of Operation will have a padding scheme and some form of key schedule.
    """

    def __init__(self, cipher):
        """
        cipher will be some form of block cipher that can encrypt/decrypt one block of data.
            - cipher.encrypt(data: bytes, key: bytes) -> bytes
            - cipher.decrypt(data: bytes, key: bytes) -> bytes
        """
        self.cipher = cipher
        self.cipher_block_size_bytes = self.cipher.block_size // 8

    def _pad(self, data: bytes) -> bytes:
        bytes_to_pad = self.cipher_block_size_bytes - 1 - (len(data) % self.cipher_block_size_bytes)
        data += b'\x80' + (b'\x00' * bytes_to_pad)
        return data

    def _unpad(self, data: bytes) -> bytes:
        data = data.rstrip(b'\x00')
        return data[:-1]

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, data: bytes, key: bytes) -> bytes:
        raise NotImplementedError


class ECB(OperationMode):
    """
    Electronic Code Book
    """

    def __init__(self, cipher, parallel=False):
        super().__init__(cipher)
        self.parallel = parallel
        if parallel:
            self.__process = self.__process_parallel

    def __process(self, data: bytes, key: bytes, encrypting: bool) -> bytes:
        process_func = self.cipher.encrypt_block if encrypting else self.cipher.decrypt_block
        if encrypting:
            data = self._pad(data)
        blocks = [process_func(data[i : i + self.cipher_block_size_bytes], key) for i in range(0, len(data), self.cipher_block_size_bytes)]
        return b''.join(blocks) if encrypting else self._unpad(b''.join(blocks))

    def __process_parallel(self, data: bytes, key: bytes, encrypting: bool) -> bytes:
        process_func = self.cipher.encrypt_block if encrypting else self.cipher.decrypt_block
        if encrypting:
            data = self._pad(data)
        with ThreadPoolExecutor(max_workers=cpu_count()) as executor:
            blocks = [data[i : i + self.cipher_block_size_bytes] for i in range(0, len(data), self.cipher_block_size_bytes)]
            futures = [executor.submit(process_func, block, key) for block in blocks]
            executor.shutdown()
            blocks = [future.result() for future in futures]
        return b''.join(blocks) if encrypting else self._unpad(b''.join(blocks))

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        return self.__process(data, key, True)

    def decrypt(self, data: bytes, key: bytes) -> bytes:
        return self.__process(data, key, False)


class CBCPaddingModes(Enum):
    Default = None
    CTS = 'CTS'
    RBT = 'RBT'


class CBC(OperationMode):
    """
    Cipher Block Chaining
    Requires an IV
    IV xor Plaintext for first block then IV becomes output of encryption for each subsequent block
    IV being non-secret transmitted with ciphertext
    """

    def __init__(self, cipher, parallel=False, padding_mode: CBCPaddingModes = CBCPaddingModes.Default):
        super().__init__(cipher)
        self.parallel = parallel
        match padding_mode:
            case CBCPaddingModes.Default:
                self.encrypt = self.__encrypt_default
                self.decrypt = self.__decrypt_default
                if parallel:
                    self.decrypt = self.__decrypt_default_parallel
            case CBCPaddingModes.CTS:
                pass
            case CBCPaddingModes.RBT:
                pass

    def __encrypt_default(self, data: bytes, key: bytes, iv: bytes = None) -> tuple[bytes, bytes]:
        if iv is None:
            iv = prng_shake256.random_bytes(self.cipher_block_size_bytes)
        if len(iv) != self.cipher_block_size_bytes:
            raise ValueError(f'IV must be {self.cipher_block_size_bytes} bytes long.')

        data = self._pad(data)
        blocks = [bytes(data) for data in batched(data, self.cipher_block_size_bytes)]
        round_iv = iv
        for i, block in enumerate(blocks):
            block = xor_words(block, round_iv)
            blocks[i] = self.cipher.encrypt_block(block, key)
            round_iv = blocks[i]
        return b''.join(blocks), iv

    def __decrypt_default(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        blocks = [bytes(data) for data in batched(data, self.cipher_block_size_bytes)]
        round_iv = iv
        for i, block in enumerate(blocks):
            blocks[i] = xor_words(self.cipher.decrypt_block(block, key), round_iv)
            round_iv = block
        return self._unpad(b''.join(blocks))

    def __decrypt_default_parallel(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        with ThreadPoolExecutor(max_workers=cpu_count()) as executor:
            blocks = [bytes(data) for data in batched(data, self.cipher_block_size_bytes)]
            futures = [executor.submit(self.cipher.decrypt_block, block, key) for block in blocks]
            executor.shutdown()
            blocks = [iv] + blocks
            blocks = [xor_words(future.result(), bytes(blocks[i - 1])) for i, future in enumerate(futures, 1)]
        return self._unpad(b''.join(blocks))


class PCBC:
    """
    Propagating Cipher Block Chaining
    """

    pass


class CFB:
    """
    Cipher FeedBack
    """

    pass


class OFB:
    """
    Output FeedBack
    """

    pass


class CTR:
    """
    Counter
    """

    def __init__(self, cipher, parallel=False):
        super().__init__(cipher)
        self.parallel = parallel

    pass


class GCM:
    """
    Galois Counter Mode
    """

    pass


def test_cipher_mode(cipher_mode, plaintext, key, only_print_failures=False):
    from time import perf_counter
    from itertools import batched

    actual_plaintext = b''
    actual_ciphertext = b''
    iv = b''

    enc_start = perf_counter()
    args = cipher_mode.encrypt(plaintext, key)
    enc_end = perf_counter()
    enc_time = enc_end - enc_start

    # ECB returns ciphertext
    # CBC returns ciphertext, iv
    if isinstance(args, tuple):
        actual_ciphertext = args[0]
        args = (actual_ciphertext, key, *args[1:])
    else:
        actual_ciphertext, args = args, (args, key)

    dec_start = perf_counter()
    actual_plaintext = cipher_mode.decrypt(*args)
    dec_end = perf_counter()
    dec_time = dec_end - dec_start

    if not only_print_failures:
        print('-' * 46)
        print(f'Cipher Mode: {cipher_mode.__class__.__name__}({cipher_mode.cipher.__class__.__name__})', '(Parallel)' if cipher_mode.parallel else '')
        print('-' * 46)
        print('Key        (inp) :'.ljust(20), key.hex().upper())
        if isinstance(cipher_mode, CBC):
            print('IV         (inp) :'.ljust(20), iv.hex().upper())

        print('Plaintext  (inp) :'.ljust(20), plaintext.hex().upper()[:10], '...', plaintext.hex().upper()[-10:])
        print('Ciphertext (out) :'.ljust(20), actual_ciphertext.hex().upper()[:10], '...', actual_ciphertext.hex().upper()[-10:])
        print('Decrypted  (out) :'.ljust(20), actual_plaintext.hex().upper()[:10], '...', actual_plaintext.hex().upper()[-10:])
        print()
        print('Encryption Time  :'.ljust(20), round(enc_time, 5), 'seconds')
        print('Decryption Time  :'.ljust(20), round(dec_time, 5), 'seconds')
        print()

    if plaintext.hex() != actual_plaintext.hex():
        act_batches = batched(plaintext, cipher_mode.cipher_block_size_bytes)
        exp_batches = batched(actual_plaintext, cipher_mode.cipher_block_size_bytes)

        try:
            for i, (exp, act) in enumerate(zip(exp_batches, act_batches, strict=True)):
                if exp == act:
                    continue
                print(f'\tBatch {i}:')
                print(f'\tExpected: {bytes(exp).hex().upper()}')
                print(f'\tActual  : {bytes(act).hex().upper()}\n')
        except ValueError:
            print('Fatal: Mismatched plaintext lengths')
            print('\tExpected:', len(plaintext))
            print('\tActual  :', len(actual_plaintext))
            print('\tExpected:', plaintext.hex().upper())
            print('\tActual  :', actual_plaintext.hex().upper())
            exit()
        print('\n')
    return enc_time, dec_time


def main():
    from time import perf_counter
    from DES import DES as DES_obj
    from AES import AES_128 as AES
    from TDES import TDES as TDES_obj

    DES = DES_obj()
    TDES = TDES_obj()

    from random import randbytes

    # AES-128-ECB parallel is faster at ~2702 bytes - 16 byte block size - ~169 blocks
    # DES-ECB parallel is faster at ~4005 bytes - 8 byte block size - ~500 blocks

    only_print_errors = False
    pt_len = 10000
    pt_start = perf_counter()
    # plaintext = randbytes(pt_len)
    plaintext = prng_shake256.random_bytes(pt_len)
    pt_end = perf_counter()
    print(f'{pt_len} byte plaintext generated in {round(pt_end - pt_start, 5)} seconds...')
    # exit()

    des_key = prng_shake256.random_bytes(8)
    ecb_des_default = ECB(DES)
    ecb_des_parallel = ECB(DES, parallel=True)
    cbc_des_default = CBC(DES)
    cbc_des_parallel = CBC(DES, parallel=True)

    tdes_key = prng_shake256.random_bytes(24)
    ecb_tdes_default = ECB(TDES)
    ecb_tdes_parallel = ECB(TDES, parallel=True)
    cbc_tdes_default = CBC(TDES)
    cbc_tdes_parallel = CBC(TDES, parallel=True)

    aes_128_key = prng_shake256.random_bytes(16)
    ecb_aes_128_default = ECB(AES)
    ecb_aes_128_parallel = ECB(AES, parallel=True)
    cbc_aes_128_cbc_default = CBC(AES)
    cbc_aes_128_cbc_parallel = CBC(AES, parallel=True)

    test_cipher_mode(ecb_des_default, plaintext, des_key, only_print_errors)
    test_cipher_mode(ecb_des_parallel, plaintext, des_key, only_print_errors)
    test_cipher_mode(ecb_tdes_default, plaintext, tdes_key, only_print_errors)
    test_cipher_mode(ecb_tdes_parallel, plaintext, tdes_key, only_print_errors)
    test_cipher_mode(ecb_aes_128_default, plaintext, aes_128_key, only_print_errors)
    test_cipher_mode(ecb_aes_128_parallel, plaintext, aes_128_key, only_print_errors)

    test_cipher_mode(cbc_des_default, plaintext, des_key, only_print_errors)
    test_cipher_mode(cbc_des_parallel, plaintext, des_key, only_print_errors)
    test_cipher_mode(cbc_tdes_default, plaintext, tdes_key, only_print_errors)
    test_cipher_mode(cbc_tdes_parallel, plaintext, tdes_key, only_print_errors)
    test_cipher_mode(cbc_aes_128_cbc_default, plaintext, aes_128_key, only_print_errors)
    test_cipher_mode(cbc_aes_128_cbc_parallel, plaintext, aes_128_key, only_print_errors)


if __name__ == '__main__':
    main()
