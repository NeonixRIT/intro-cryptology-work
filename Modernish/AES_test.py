from AES import AES, State, xor_words, GF_256_multiply, words_to_bytes

# https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=901427

AES_128 = AES(4, 10)
AES_192 = AES(6, 12)
AES_256 = AES(8, 14)

AES_TEST_INPUT = bytes([
    0x32, 0x43, 0xf6, 0xa8,
    0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2,
    0xe0, 0x37, 0x07, 0x34
])

AES_TEST_INPUT_STATE = State(bytes([
    0x32, 0x43, 0xf6, 0xa8,
    0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2,
    0xe0, 0x37, 0x07, 0x34
]))

AES_128_TEST_KEY = bytes([
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
])

AES_192_TEST_KEY = bytes([
    0x8e, 0x73, 0xb0, 0xf7,
    0xda, 0x0e, 0x64, 0x52,
    0xc8, 0x10, 0xf3, 0x2b,
    0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2,
    0x52, 0x2c, 0x6b, 0x7b
])

AES_256_TEST_KEY = bytes([
    0x60, 0x3d, 0xeb, 0x10,
    0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0,
    0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07,
    0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3,
    0x09, 0x14, 0xdf, 0xf4
])


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
    expected_result = 0xc1
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
