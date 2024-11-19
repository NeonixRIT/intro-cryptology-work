from AES import AES, State, xor_words, GF_256_multiply, words_to_bytes

# https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=901427

AES_128 = AES(4, 10)
AES_192 = AES(6, 12)
AES_256 = AES(8, 14)

AES_TEST_INPUT = bytes([0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34])

AES_TEST_INPUT_STATE = State(bytes([0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34]))

AES_128_TEST_KEY = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C])

AES_192_TEST_KEY = bytes([0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B])

AES_256_TEST_KEY = bytes([0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81, 0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4])


def test_xor_words():
    a = b'\x00\x11\x22\x33'
    b = b'\x44\x55\x66\x77'
    expected_result = b'\x44\x44\x44\x44'
    assert xor_words(a, b) == expected_result


def test_words_to_bytes():
    words = [b'\x00\x11\x22\x33', b'\x44\x55\x66\x77']
    expected_result = b'\x00\x11\x22\x33\x44\x55\x66\x77'
    assert words_to_bytes(words) == expected_result


def test_gf_256_mul():
    a = 0x57
    b = 0x83
    expected_result = 0xC1
    assert GF_256_multiply(a, b) == expected_result


def test_128_byte_sub():
    pass


def test_128_inv_byte_sub():
    pass


def test_192_byte_sub():
    pass


def test_192_inv_byte_sub():
    pass


def test_256_byte_sub():
    pass


def test_256_inv_byte_sub():
    pass


def test_128_g():
    pass


def test_192_g():
    pass


def test_256_g():
    pass


def test_shift_row():
    pass


def test_inv_shift_row():
    pass


def test_mix_column():
    pass


def test_inv_mix_column():
    pass


def test_xor_state():
    pass


def test_ksa_128():
    pass


def test_ksa_192():
    pass


def test_ksa_256():
    pass


def test_enc_block_128():
    pass


def test_enc_block_192():
    pass


def test_enc_block_256():
    pass


def test_dec_block_128():
    pass


def test_dec_block_192():
    pass


def test_dec_block_256():
    pass
