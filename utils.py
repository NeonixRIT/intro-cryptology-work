import numpy as np
import sympy as sp

from sys import byteorder
from functools import cache
from random import randint, shuffle, seed

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


def shift_left(items: str | list, shift: int) -> str | list:
    if shift % len(items) == 0:
        return items
    return items[shift:] + items[:shift]


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


@cache
def xor_bits(a: str, b: str) -> str:
    return ''.join([str(int(a[i]) ^ int(b[i])) for i in range(len(a))])


@cache
def xor_words(a, b):
    a_bits = ''.join(a)
    b_bits = ''.join(b)
    res_bits = xor_bits(a_bits, b_bits)
    return chunk_string(res_bits, 8)


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


def feistel_system(inp: str, f, ksa, block_size: int, rounds: int, is_bits: bool = False) -> str:
    if len(inp) % 2 != 0:
        inp += '\0'
    l_half = inp[:len(inp) // 2]
    r_half = inp[len(inp) // 2:]
    if not is_bits:
        l_half = ''.join([str(bit) for bit in string_to_bits(l_half)]).zfill(block_size)
        r_half = ''.join([str(bit) for bit in string_to_bits(r_half)]).zfill(block_size)
    else:
        l_half = l_half.zfill(block_size // 2)
        r_half = r_half.zfill(block_size // 2)

    for _ in range(rounds):
        l_half, r_half = r_half, xor_bits(l_half, f(r_half, next(ksa)))

    l_half, r_half = r_half, l_half
    return l_half + r_half


def feistel_system_keys(inp: str, f, keys, block_size: int, rounds: int, is_bits: bool = False) -> str:
    if len(inp) % 2 != 0:
        inp += '\0'
    l_half = inp[:len(inp) // 2]
    r_half = inp[len(inp) // 2:]
    if not is_bits:
        l_half = ''.join([str(bit) for bit in string_to_bits(l_half)]).zfill(block_size)
        r_half = ''.join([str(bit) for bit in string_to_bits(r_half)]).zfill(block_size)
    else:
        l_half = l_half.zfill(block_size // 2)
        r_half = r_half.zfill(block_size // 2)

    for i in range(rounds):
        l_half, r_half = r_half, xor_bits(l_half, f(r_half, keys[i]))

    l_half, r_half = r_half, l_half
    return l_half + r_half


@cache
def example_f(bits: str, key: int):
    # 1
    num = int(bits[::-1], 2)
    # 2
    ki = (num ** 3 + key) % 16
    return bin(ki)[2:].zfill(len(bits))


def example_ksa(key: str, rounds: int):
    for _ in range(rounds):
        key = f'{(int(key[2]) + int(key[3])) % 2}{key[0]}{key[1]}{key[2]}'
        yield int(key, 2)


@cache
def permute(inp: str, permutation: tuple[int], base: int = 1):
    return ''.join([inp[i - base] for i in permutation])


def inverse_permute(permutation: tuple[int], base: int = 1):
    return tuple([permutation.index(i) + base for i in range(base, len(permutation) + 1)])


def bits_to_poly(bits: str, domain=sp.FiniteField(2)):
    if sum([int(bit) for bit in bits]) == 0:
        return sp.Poly('x*0', sp.Symbol('x'), domain=domain)
    if bits[-1] == '1':
        return sp.Poly('x**0', sp.Symbol('x'), domain=domain)
    return sp.Poly(('+' if sum([int(bit) for bit in bits]) > 1 else '').join([f'x**{7 - i}' if i != 7 else '1' for i in range(8) if bits[i] == '1']), domain=domain)


def letter_to_poly(letter, domain=sp.FiniteField(2)):
    letter = bin(ord(letter))[2:].zfill(8)
    return bits_to_poly(letter, domain)


def poly_to_letter(poly: sp.Poly):
    return chr(int(''.join([str(bit) for bit in poly.all_coeffs()]), 2))


def poly_to_byte(poly: sp.Poly):
    return ''.join([str(bit) for bit in poly.all_coeffs()]).zfill(8)


def euclidian_alg_gcd(a, b):
    if b > a:
        a, b = b, a

    while True:
        r = a % b
        if r <= 0:
            return b
        a = b
        b = r


def euclidian_alg_gcd_verbose(a, b, tabs=1):
    orig_a = a
    orig_b = b

    if b > a:
        a, b = b, a

    while True:
        print('\t' * tabs, f'gcd({a}, {b})', sep='')
        r = a % b
        print('\t' * tabs, f'{a} mod {b} = {r}', sep='')
        if r <= 0:
            print('\t' * tabs, f'gcd({b}, {r}) = {b}', sep='')
            print('\t' * tabs, f'gcd({orig_a}, {orig_b}) = {b}\n', sep='')
            return b
        a = b
        b = r


@cache
def is_prime_default(n: int) -> bool:
    if n == 2:
        return True
    if n % 2 == 0 or n < 2:
        return False
    for i in range(3, int(n ** 0.5) + 1, 2):
        if n % i == 0:
            return False
    return True


def is_prime_fermat(n: int, k: int = 10) -> bool:
    if n == 2:
        return True
    if n % 2 == 0 or n < 2:
        return False
    if n == 3:
        return True
    for _ in range(k):
        a = randint(3, n - 2) # doesnt account for duplicates :(
        if euclidian_alg_gcd(a, n) != 1 or square_exponentiation(a, n - 1, n) != 1:
            return False
    return True


@cache
def prime_factors(n):
    factors = set()
    while n % 2 == 0:
        factors.add(2)
        n //= 2

    for i in range(3, int(n**0.5) + 1, 2):
        while n % i == 0:
            factors.add(i)
            n //= i

    if n > 2:
        factors.add(n)

    return factors


def prime_factors_verbose(n):
    factors = []
    while n % 2 == 0:
        factors.append(2)
        n //= 2

    for i in range(3, int(n**0.5) + 1, 2):
        while n % i == 0:
            factors.append(i)
            n //= i

    if n > 2:
        factors.append(n)

    return factors


def mod_inverse_fermat(a: int, p: int) -> int:
    '''
    a ^ (p - 1) = 1 (mod p)
    only works if modulus p is prime
    '''
    if euclidian_alg_gcd(a, p) != 1 or not is_prime_default(p):
        return -1
    return square_exponentiation(a, p - 2, p)


def mod_inverse_fermat_verbose(a: int, p: int) -> int:
    '''
    a ^ (p - 1) = 1 (mod p)
    only works if modulus p is prime
    and a is not divisible by p
    IE: a and p are coprime
    '''
    print('\t\ta ^ (p - 1) ≣ 1 mod p')
    print('\t\ta * [a ^ (p - 2)] mod p = 1')
    print('\t\ta⁻¹ ≣ a ^ [p - 2] mod p')
    print(f'\t\t{a}⁻¹ ≣ {a} ^ ({p - 2}) mod {p}')
    if euclidian_alg_gcd(a, p) != 1 or not is_prime_default(p):
        print(f'\t\tthe inverse mod of {a} with respect to {p} doesn\'t exist. (a and p are not coprime or p is not prime).')
        return -1
    res = square_exponentiation(a, p - 2, p)
    print(f'\t\tthe inverse mod of {a} with respect to {p} is {res}\n')
    return res


@cache
def eulers_phi(n: int) -> int:
    if is_prime_default(n):
        return n - 1

    phi = n
    for p in prime_factors(n):
        phi *= (1 - (1 / p))

    return int(phi)


def eulers_phi_verbose(n: int, tabs=1) -> int:
    if is_prime_default(n):
        print('\t' * tabs, f'{n} is prime', sep='')
        print('\t' * tabs, f'φ({n}) = {n - 1}', sep='')
        print()
        return n - 1

    p_factors = prime_factors_verbose(n)
    print('\t' * tabs, f'prime factors of {n}: {p_factors}', sep='')

    exp_dict = {}
    for val in p_factors:
        if val not in exp_dict:
            exp_dict[val] = 1
        else:
            exp_dict[val] += 1

    x = np.log2(n / np.product(np.array(p_factors[1:])))
    expr = ' * '.join([f'({p} ^ {exp})' for p, exp in exp_dict.items()])
    print('\t' * (tabs + 1), f'{expr} = {n}', sep='')
    res = ''
    vals = []
    for e in expr.split(' * '):
        p, x = e[1: -1].split(' ^ ')
        res += f'[({p} ^ {x}) - ({p} ^ {int(x) - 1})] * '
        vals.append((int(p) ** int(x)) - (int(p) ** (int(x) - 1)))
    print('\t' * (tabs + 1), res[:-3], sep='')
    print('\t' * (tabs + 1), ' * '.join([str(v) for v in vals]), ' = ', np.product(np.array(vals)), sep='')
    print()
    return int(np.product(np.array(vals)))


def eulers_phi_base(n: int) -> int:
    return len([i for i in range(1, n) if sp.gcd(i, n) == 1])


@cache
def extended_euclidean(a: int, b: int):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_euclidean(b % a, a)
        return gcd, y - (b // a) * x, x


def extended_euclidean_verbose(a: int, b: int):
    print(f'\t{a}⁻¹ mod {b}:')
    if euclidian_alg_gcd_verbose(a, b, 2) != 1:
        print(f'\t\tgcd of {a} and {b} does not equal 1\n')
        return -1, -1
    orig_b = b
    print('\t\ti\tq\tr\ts\tt')
    print('\t\t0\tx\tx\t1\t0')
    s0, s1 = 1, 0
    t0, t1 = 0, 1

    i = 1
    while a % b != 0:
        q = a // b
        r = a % b
        s = s0 - q * s1
        t = t0 - q * t1
        if i == 1:
            print('\t\t1\tx\tx\t0\t1')
        else:
            print(f'\t\t{i}\t{q}\t{r}\t{t}\t{s}')
        a, b = b, r
        s0, s1 = s1, s
        t0, t1 = t1, t
        i += 1
    print()
    return s % orig_b, t % orig_b


def mod_inverse_euler(a: int, b: int) -> int:
    '''
    a * x ≣ 1 mod b
    '''
    if euclidian_alg_gcd(a, b) != 1:
        return -1
    m = eulers_phi(b)
    return a ** (m - 1) % b


def mod_inverse_euler_verbose(a: int, b: int) -> int:
    '''
    a * x ≣ 1 mod b
    '''
    if euclidian_alg_gcd(a, b) != 1:
        print(f'\t\tThe inverse mod of {a} with respect to {b} doesn\'t exist. (a and b are not coprime).')
        print(f'\t\t{a} * x ≣ 1 mod {b}')
        print('\t\tx does not exist')
        return -1
    m = eulers_phi_verbose(b, tabs=2)
    print(f'\t\tφ({b}) = {m}')
    x = a ** (m - 1) % b
    print('\t\tx = a ^ (m - 1) mod b')
    print(f'\t\tx = {a} ^ {m - 1} mod {b}')
    print(f'\t\tx = {x}')
    print(f'\t\t{a} * {x} ≣ 1 mod {b}')
    print()
    return x


def inverse_mod(a: int, b: int) -> int:
    '''
    a * x ≣ 1 mod b
    '''
    if euclidian_alg_gcd(a, b) != 1:
        return -1
    if is_prime_fermat(b):
        return mod_inverse_fermat(a, b)
    return mod_inverse_euler(a, b) % b


def inverse_mod_verbose(a: int, b: int) -> int:
    '''
    a * x ≣ 1 mod b
    '''
    print(f'\t{a}⁻¹ mod {b}:')
    if euclidian_alg_gcd_verbose(a, b, tabs=2) != 1:
        return -1
    print(f'\t\t{a} and {b} are coprime. (gcd({a}, {b}) = 1)')
    if is_prime_fermat(b):
        print(f'\t\t{b} is prime. Using Fermat\'s Little Theorem: a ^ (p - 1) ≣ 1 mod p)')
        return mod_inverse_fermat_verbose(a, b)
    print(f'\t\t{b} is not prime. Using Euler\'s Theorem: a ^ (φ(p) - 1) ≣ 1 mod p)')
    return mod_inverse_euler_verbose(a, b) % b


@cache
def square_exp_round_func(base: int, y: int, bit: int, mod: int) -> int:
    y = (y ** 2) % mod
    if bit == 1:
        y = (y * base) % mod
    return y


@cache
def square_exponentiation(base: int, exponent: int, mod: int) -> int:
    y = base
    exponent = [int(x) for x in bin(exponent)[3:]]
    for bit in exponent:
        y = square_exp_round_func(base, y, bit, mod)
    return y


def solve_discrete_log(base: int, n: int, mod: int):
    for i in range(1, mod):
        if (base ** i) % mod == n:
            return i
    return -1


def solve_discrete_log_verbose(base: int, n: int, mod: int, tabs: int = 1, print_step_interval: int = 50):
    print('\t' * tabs, f'{base}^x mod {mod} = {n}:', sep='')
    for i in range(1, mod):
        if (base ** i) % mod == n:
            if i != 1 or i % print_step_interval != 0:
                print('\t' * tabs, f'\t{base}^{i} mod {mod} = {n} ✅\n', sep='')
            else:
                print('\t' * tabs, f'\t{base}^{i} mod {mod} = {n} ✅\n', sep='')
            return i
        if i % print_step_interval == 0 or i == 1:
            print('\t' * tabs, f'\t{base}^{i} mod {mod} = {n} ❌', sep='')
    print('\t' * tabs, f'\t{base}^{i} mod {mod} = {n} ❌\n', sep='')
    return -1


def square_exponentiation_default(base: int, exponent: int, mod: int) -> int:
    return (base ** exponent) % mod


def square_exponentiation_verbose(base: int, exponent: int, mod: int, tabs: int = 1) -> int:
    y = base
    binary_exp = bin(exponent)[2:]
    print('\t' * tabs, 'x'.ljust(len(str(base))), ' ^ ', 'H'.ljust(len(str(exponent))), ' mod m:', sep='')
    print('\t' * tabs, f'{base} ^ {exponent} mod {mod}:', sep='')
    exponent = [int(x) for x in bin(exponent)[3:]]
    print('\t' * tabs, '\ti\th\ty\ty²\ty * x\texponent₂', sep='')
    print('\t' * tabs, f'\t{0}\t{binary_exp[0]}\t{y}\tX\tX\t{binary_exp[0]}', sep='')
    for i, bit in enumerate(exponent):
        temp_a = y
        y = (y ** 2) % mod
        temp_b = y
        if bit == 1:
            y = (y * base) % mod
        if i == len(exponent) - 1:
            print('\t' * tabs, f'\t{i + 1}\t{binary_exp[i + 1]}\t{y}\tX\tX\t{binary_exp[:i + 2]}', sep='')
        else:
            print('\t' * tabs, f'\t{i + 1}\t{binary_exp[i + 1]}\t{temp_a}\t{temp_b}\t{y if int(binary_exp[i + 1]) == 1 else "X"}\t{binary_exp[:i + 2]}', sep='')
    print()
    return y


def chinese_remainder_theorem(x: int, d: int, p: int, q: int) -> int:
    # step 1a: x_p and x_q
    x_p = x % p
    x_q = x % q

    # step 1b: d_p and d_q
    d_p = d % (p - 1)
    d_q = d % (q - 1)

    # step 2: exponentiation
    y_p = square_exponentiation(x_p, d_p, p)
    y_q = square_exponentiation(x_q, d_q, q)

    # step 3: inverse transformation
    _, c_p, c_q = extended_euclidean(q, p)
    c_p, c_q = c_p % p, c_q % q

    # return result
    return ((q * c_p) * y_p + (p * c_q) * y_q) % (p * q)


def crt_default(x: int, d: int, p: int, q: int) -> int:
    return (x ** d) % (p * q)


def crt_builtin(x: int, d: int, p: int, q: int) -> int:
    return pow(x, d, p * q)


def time_function(func, *args, **kwargs):
    from time import perf_counter
    start = perf_counter()
    res = func(*args, **kwargs)
    stop = perf_counter()
    return stop - start, res


def compare_function_times(runs, f1, f2, *args, **kwargs):
    total1 = 0
    total2 = 0
    for i in range(runs):
        if i % 2 == 0:
            delta1_1, res1 = time_function(f1, *args, **kwargs)
            delta2_1, res2 = time_function(f2, *args, **kwargs)
            delta2_2, _ = time_function(f2, *args, **kwargs)
            delta1_2, _ = time_function(f1, *args, **kwargs)

            total1 += (delta1_1 + delta1_2) / 2
            total2 += (delta2_1 + delta2_2) / 2
        else:
            delta2_1, _ = time_function(f2, *args, **kwargs)
            delta1_1, _ = time_function(f1, *args, **kwargs)
            delta1_2, _ = time_function(f1, *args, **kwargs)
            delta2_2, _ = time_function(f2, *args, **kwargs)

            total1 += (delta1_1 + delta1_2) / 2
            total2 += (delta2_1 + delta2_2) / 2

    delta1 = total1 / (runs * 4)
    delta2 = total2 / (runs * 4)
    l_name = max(len(f1.__name__), len(f2.__name__))
    if delta1 < delta2:
        print(f'{f1.__name__}'.ljust(l_name + 10), f'{round(delta2 - delta1, 9)}s'.rjust(15), res1)
    else:
        print(f'{f2.__name__}'.ljust(l_name + 10), f'{round(delta1 - delta2, 9)}s'.rjust(15), res2)


def time_square_exp():
    runs = 5
    rounds = 10
    scalar = 88
    max_val = 10 ** scalar
    min_val = 9 ** scalar
    seed(scalar)
    for i in range(rounds):
        numbers = [randint(min_val, max_val), randint(min_val, max_val), randint(min_val, max_val)]
        print(f'Round {i + 1}:'.ljust(len(str(rounds)) + 6 + 5), end=' ' * 5)
        compare_function_times(runs, square_exponentiation_default, square_exponentiation, numbers[0], numbers[1], numbers[2])


def time_crt(compare_builtin: bool = False):
    import sys
    sys.setrecursionlimit(10 ** 6)
    runs = 5
    rounds = 20
    scalar = 1
    max_val = 10 ** scalar
    min_val = 6 ** scalar
    seed(scalar)

    f2 = crt_builtin if compare_builtin else crt_default
    for i in range(rounds):
        numbers = [randint(min_val, max_val), randint(min_val, max_val), randint(min_val // 3, max_val // 3), randint(min_val // 3, max_val // 3)]
        print(f'Round {i + 1}:'.ljust(len(str(rounds)) + 6 + 5), end=' ' * 5)
        compare_function_times(runs, chinese_remainder_theorem, f2, numbers[0], numbers[1], numbers[2], numbers[3])


def main():
    p, q = 3, 11
    n = p * q
    phi = eulers_phi(n)
    es = [i for i in range(1, phi) if euclidian_alg_gcd(i, phi) == 1]
    ds = [inverse_mod(val, n) for val in es]
    for i in range(len(es)):
        print(f'e={es[i]}, d={ds[i]}')


if __name__ == '__main__':
    main()
