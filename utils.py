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


def string_to_bits(s: str):
    return [int(bit) for bit in ''.join([bin(ord(c))[2:].zfill(8) for c in s])]


def string_to_bytes(s: str):
    return [int(byte, 2) for byte in [bin(ord(c))[2:].zfill(8) for c in s]]


def lsfr(degree: int, gates: list[int], init_state: str, length: int = 1000, verbos: bool = False) -> list:
    if len(init_state) < degree:
        raise ValueError("The initial state must be at least as long as the degree of the LSFR.")
    gates = [-1 - i for i in gates]
    blocks = [int(init_state[i]) for i in range(degree)]
    for _ in range(length):
        if gates:
            blocks.append(sum([blocks[i] for i in gates]) % 2)
        else:
            blocks.append(blocks[-1])
        blocks = shift_right(blocks, 1)
        out = blocks[-1]
        del blocks[-1]
        if verbos:
            print(blocks)
        yield out
