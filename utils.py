from sys import byteorder

LIGHT_GREEN = '\033[1;32m'
LIGHT_RED = '\033[1;31m'
CYAN = '\u001b[36m'
WHITE = '\033[0m'


def read_file_to_words(path):
    res = set()
    with open(path) as file:
        for line in file:
            res.add(line.upper().strip())
    return res


EN_DICTIONARY = read_file_to_words('./data/words_alpha.txt')


def read_all_to_string(path):
    res = ''
    with open(path) as file:
        for line in file:
            res += line.upper().strip() + ' '
        return res


def bool_prompt(prompt: str, default_output: bool) -> bool:
    y_str = 'Y' if default_output else 'y'
    n_str = 'N' if not default_output else 'n'
    result = input(f'{prompt} ({LIGHT_GREEN}{y_str}{WHITE}/{LIGHT_RED}{n_str}{WHITE}): ')
    return default_output if not result else True if result.lower() == 'y' else False if result.lower() == 'n' else default_output


def wrap(num, shift):
    res = (num + (shift % 26)) % 91
    if res < 65:
        res += 65
    return res


def is_valid_char(char: str) -> bool:
    return ord(char) in range(65, 91)


def strip_string(string: str, is_valid_char=is_valid_char) -> str:
    return ''.join([char for char in string if is_valid_char(char)])


def chunk_string(string: str, chunk_size: int, convert_ascii: bool = False, ascii_base: int = 65) -> list[str]:
    if convert_ascii:
        return [[ord(char) - ascii_base for char in string[chunk_size * i:chunk_size * (i + 1)]] for i in range(0, len(string) // chunk_size + 1) if string[chunk_size * i:chunk_size * (i + 1)]]
    return [string[i:i + chunk_size] for i in range(0, len(string), chunk_size)]


def shift_right(items: str | list, shift: int) -> str | list:
    if shift % len(items) == 0:
        return items
    return items[-shift:] + items[:-shift]


def string_to_bits(s: str, char_size: int = 8):
    return [int(bit) for bit in ''.join([bin(ord(c))[2:].zfill(char_size) for c in s])]


def string_to_ints(s: str):
    return [int(byte, 2) for byte in [bin(ord(c))[2:].zfill(8) for c in s]]


def string_to_bytes(s: str):
    return [int.to_bytes(ord(char)) for char in s]


def bits_to_bytes(s: str, chunk_size: int = 8):
    return [int.to_bytes(int(byte, 2)) for byte in chunk_string(s, chunk_size)]


def bytes_to_string(b: list[bytes], encoding: str = 'utf-8'):
    return b''.join(b).decode(encoding)

def bytes_to_ints(b: list[bytes]):
    return [int.from_bytes(byte, byteorder=byteorder) for byte in b]


def xor_bits(a: str, b: str) -> str:
    return ''.join([str(int(a[i]) ^ int(b[i])) for i in range(len(a))])


def lsfr(degree: int, gates: list[int], init_state: str, length: int = 1000, verbos: bool = False) -> list:
    if len(init_state) < degree:
        raise ValueError("The initial state must be at least as long as the degree of the LSFR.")


    gates = [-1 - i for i in gates]
    blocks = [int(init_state[i]) for i in range(degree)]

    if verbos:
        print()
        print('bit', str([f's{i}' for i in range(degree)]).replace('\'', ''), 'out')
        print('---', str([str(bit).rjust(2) for bit in blocks]).replace('\'', ''), '---')

    for i in range(length):
        if gates:
            blocks.append(sum([blocks[i] for i in gates]) % 2)
        else:
            blocks.append(blocks[-1])
        blocks = shift_right(blocks, 1)
        out = blocks[-1]
        del blocks[-1]
        if verbos:
            print(f'{i + 1}'.ljust(3), str([str(bit).rjust(2) for bit in blocks]).replace('\'', '').ljust(2 * degree), out)
        yield out


def feistel_system_round(l_half: str, r_half: str, f, key) -> str:
    # Take text, split in half.
    # if not even size, padd smalled half with nullbyte
    # Apply f to the right half, XOR with the left half.
    # Right becomes left, xor result becomes right.
    # Repeat for round number of rounds
    l_half, r_half = r_half, xor_bits(l_half, f(r_half, key))

    print(''.join([str(char) for char in l_half]), ''.join([str(char) for char in r_half]))
    print()
    # exit()

    # return r_half, f(r_half) ^ l_half


def feistel_system(inp: str, f, ksa, block_size: int, rounds: int, is_bits: bool = False) -> str:
    if len(inp) % 2 != 0:
        inp += '\0'
    l_half = inp[:len(inp) // 2]
    r_half = inp[len(inp) // 2:]
    if not is_bits:
        l_half = ''.join([str(bit) for bit in string_to_bits(l_half)]).zfill(block_size)
        r_half = ''.join([str(bit) for bit in string_to_bits(r_half)]).zfill(block_size)
    else:
        l_half = l_half.zfill(block_size)
        r_half = r_half.zfill(block_size)

    for _ in range(rounds):
        l_half, r_half = r_half, xor_bits(l_half, f(r_half, next(ksa)))

    l_half, r_half = r_half, l_half
    return l_half + r_half


def example_f(bits: str, key: int):
    # 1
    num = int(bits[::-1], 2)
    # 2
    ki = (num ** 3 + key) % 16
    return bin(ki)[2:].zfill(len(bits))


def example_ksa(key: str, rounds: int):
    for _ in range(rounds):
        key = f'{int(key[2]) + int(key[3]) % 2}{key[0]}{key[1]}{key[2]}'
        yield int(key, 2)
