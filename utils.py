import numpy as np
import sympy as sp
import threading

from sys import byteorder, setrecursionlimit
from functools import cache, wraps
from hashlib import sha256
from multiprocessing import Pool, cpu_count
from queue import Queue
from random import randint, seed, randrange, choice, SystemRandom
from time import perf_counter, sleep

LIGHT_GREEN = '\033[1;32m'
LIGHT_RED = '\033[1;31m'
CYAN = '\u001b[36m'
WHITE = '\033[0m'

setrecursionlimit(10 ** 8)


def firstresult(func):
    '''
    Decorator that runs multiple instances of a function and returns the first result
    Supposed to interupt the execution of the function if the result is found
    But doesnt work...
    '''
    queue = Queue()

    @wraps(func)
    def wrapper(*args, **kwargs):
        def _wrapper():
            queue.put(func(*args, **kwargs))
        threads = [threading.Thread(target=_wrapper) for _ in range(cpu_count())]

        for thread in threads:
            thread.start()

        result = queue.get()
        return result

    return wrapper


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


def string_to_number(string: str, char_size: int = 8) -> int:
    # return int.from_bytes(string.encode(encoding=f'utf-{char_size}'), 'big')
    return int(''.join([bin(ord(x))[2:].zfill(char_size) for x in string]), 2)


def number_to_string(number: int, char_size: int = 8) -> str:
    # return number.to_bytes((number.bit_length() + 7) // 8, 'big').decode(encoding=f'utf-{char_size}')
    binary = bin(number)[2:].zfill(char_size * (len(bin(number)[2:]) // char_size + 1))
    return ''.join([chr(int(byte_letter, 2)) for byte_letter in chunk_string(binary, char_size)])


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


@cache
def euclidean_alg_gcd_recur(a, b):
    if b == 0:
        return a
    if a == 0:
        return b
    if b > a:
        a, b = b, a
    return euclidean_alg_gcd_recur(b, a % b)


@cache
def euclidean_alg_gcd(a, b):
    if b == 0:
        return a
    if a == 0:
        return b

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
def is_prime_from_list(n: int, primes: tuple[int]) -> bool:
    for prime in primes:
        if n % prime == 0 and prime ** 2 <= n:
            return False
    return True


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
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    for _ in range(k):
        a = randint(2, n - 2) # doesnt account for duplicates :(
        if euclidean_alg_gcd(a, n) != 1 or square_exponentiation(a, n - 1, n) != 1:
            return False
    return True


def is_prime_miller(n: int, s: int = 10):
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r = n - 1
    u = 0
    while r % 2 == 0:
        u += 1
        r //= 2

    for _ in range(s):
        a = randint(2, n - 2)
        z = square_exponentiation(a, r, n)
        if z == 1 or z == n - 1:
            continue
        for _ in range(u - 1):
            z = square_exponentiation(z, 2, n)
            if z == n - 1:
                break
        else:
            return False
    return True


def is_perfect_square(c: int):
    if c == 1 or c == 0:
        return True
    if c < 0 or c == 2 or c == 3:
        return False

    bits = c.bit_length()
    n = 2 ** (bits - 1)
    n = (n + n // 2).bit_length()
    m = n // 2 + 1

    xi = int((1 / 2) * (c ** 0.5)) + (2 ** (m - 1))
    while True:
        xi = (xi ** 2 + c) // (2 * xi)
        if (xi ** 2) < (2 ** m + c):
            break

    if int(xi ** 2) == c:
        return True
    return False


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


def prime_factors_vector(n: int) -> list[int]:
    factors = [0]
    while n % 2 == 0:
        factors[0] += 1
        n //= 2

    index = 1
    last_value = 0
    for i in range(3, int(n**0.5) + 1, 2):
        factors.append(0)
        while n % i == 0:
            factors[index] += 1
            last_value = index
            n //= i
        index += 1

    if n > 2:
        factors.append(1)
        last_value = index

    return factors[:last_value + 1]


def pollards_rho(n):
    if n % 2 == 0:
        return 2
    x = y = randint(1, n - 1)
    c = randint(1, n - 1)
    d = 1

    while d == 1:
        x = square_exponentiation(x, 2, n) + c % n
        y = square_exponentiation(y, 2, n) + c % n
        y = square_exponentiation(y, 2, n) + c % n
        d = euclidean_alg_gcd(abs(x - y), n)
    if d == n and not is_prime_miller(n):
        return pollards_rho(n)
    return d


@cache
def prime_factors_pollards(n):
    if n <= 1:
        return []

    factor = pollards_rho(n)
    if factor == n:
        return [n]

    factors = prime_factors(factor)
    factors.extend(prime_factors(n // factor))

    return factors


def pollards_rho_cycle_check(x0, func):
    tortoise = func(x0)
    hare = func(func(x0))
    while tortoise != hare:
        tortoise = func(tortoise)
        hare = func(func(hare))

    mu = 0
    tortoise = x0
    while tortoise != hare:
        tortoise = func(tortoise)
        hare = func(hare)
        mu += 1

    lam = 1
    hare = func(tortoise)
    while tortoise != hare:
        hare = func(hare)
        lam += 1

    return lam, mu


def brents_pollards_rho(n):
    if n % 2 == 0:
        return 2

    c = randint(1, n - 1)
    hare = tortoise = randint(1, n - 1)
    m = randint(1, n - 1)
    d, lam, z = 1, 1, 1
    while d == 1:
        tortoise = hare
        for _ in range(lam):
            hare = (square_exponentiation(hare, 2, n) + c) % n

        k = 0
        while k < lam and d == 1:
            ys = hare
            for _ in range(min(m, lam - k)):
                hare = (square_exponentiation(hare, 2, n) + c) % n
                z = z * abs(tortoise - hare) % n
            d = euclidean_alg_gcd(z, n)
            k += m
        lam *= 2

    if d == n:
        while True:
            ys = (square_exponentiation(ys, 2, n) + c) % n
            d = euclidean_alg_gcd(abs(tortoise - ys), n)
            if d > 1:
                break
    if d == n and not is_prime_miller(n):
        return brents_pollards_rho(n)
    return d


def brents_cycle_check(x0, func, verbose=False):
    lam = p = 1
    tortoise = x0
    hare = func(x0)
    m = 1
    while tortoise != hare:
        if lam == p:
            tortoise = hare
            p *= 2
            lam = 0
        for _ in range(m):
            hare = func(hare)
            if hare == tortoise:
                break
        if verbose:
            print(f'\tt={tortoise}, h={hare}')
        lam += m

    tortoise = hare = x0
    if verbose:
        print()
        print(f'\tt={tortoise}, h={hare}')
    for _ in range(lam):
        hare = func(hare)
        if verbose:
            print(f'\tt={tortoise}, h={hare}')

    if verbose:
        print()
        print(f'\tt={tortoise}, h={hare}')
    mu = 0
    while tortoise != hare:
        tortoise = func(tortoise)
        hare = func(hare)
        if verbose:
            print(f'\tt={tortoise}, h={hare}')
        mu += 1

    return lam, mu


def brents_cycle_check_ec(xy0, func, mod, a, verbose=False):
    lam = p = 1
    tortoise = xy0
    hare = func(xy0, xy0, mod, a)
    m = 1
    while tortoise != hare:
        if lam == p:
            tortoise = hare
            p *= 2
            lam = 0
        for _ in range(m):
            hare = func(hare, xy0, mod, a)
            if hare == tortoise:
                break
        if verbose:
            print(f'\tt={tortoise}, h={hare}')
        lam += m

    tortoise = hare = xy0
    if verbose:
        print()
        print(f'\tt={tortoise}, h={hare}')
    for _ in range(lam):
        hare = func(hare, xy0, mod, a)
        if verbose:
            print(f'\tt={tortoise}, h={hare}')

    if verbose:
        print()
        print(f'\tt={tortoise}, h={hare}')
    mu = 0
    while tortoise != hare:
        tortoise = func(tortoise, xy0, mod, a)
        hare = func(hare, xy0, mod, a)
        if verbose:
            print(f'\tt={tortoise}, h={hare}')
        mu += 1

    return lam, mu


@cache
def prime_factors_brents(n):
    if n <= 1:
        return []

    factor = brents_pollards_rho(n)
    if factor == n:
        return [n]

    factors = prime_factors_brents(factor)
    factors.extend(prime_factors_brents(n // factor))

    return factors


def mod_inverse_fermat(a: int, p: int) -> int:
    '''
    a ^ (p - 1) = 1 (mod p)
    only works if modulus p is prime
    '''
    if euclidean_alg_gcd(a, p) != 1 or not is_prime_default(p):
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
    if euclidean_alg_gcd(a, p) != 1 or not is_prime_default(p):
        print(f'\t\tthe inverse mod of {a} with respect to {p} doesn\'t exist. (a and p are not coprime or p is not prime).')
        return -1
    res = square_exponentiation(a, p - 2, p)
    print(f'\t\tthe inverse mod of {a} with respect to {p} is {res}\n')
    return res


@cache
def eulers_phi(n: int) -> int:
    if is_prime_miller(n):
        return n - 1

    phi = n
    for p in prime_factors_brents(n):
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


def extended_euclidean_default(a: int, b: int):
    if euclidean_alg_gcd(a, b) != 1:
        return -1, -1
    orig_b = b
    s0, s1 = 1, 0
    t0, t1 = 0, 1

    i = 1
    while a % b != 0:
        q = a // b
        r = a % b
        s = s0 - q * s1
        t = t0 - q * t1
        a, b = b, r
        s0, s1 = s1, s
        t0, t1 = t1, t
        i += 1
    return s % orig_b, t % orig_b


def extended_euclidean_verbose(a: int, b: int, tabs: int = 1):
    print('\t' * tabs + f'{a}⁻¹ mod {b}:')
    if euclidian_alg_gcd_verbose(a, b, tabs + 1) != 1:
        print('\t' * tabs + f'\tgcd of {a} and {b} does not equal 1\n')
        return -1, -1
    orig_b = b
    print('\t' * tabs + '\ti\tq\tr\ts\tt')
    print('\t' * tabs + '\t0\tx\tx\t1\t0')
    s0, s1 = 1, 0
    t0, t1 = 0, 1

    i = 1
    while a % b != 0:
        q = a // b
        r = a % b
        s = s0 - q * s1
        t = t0 - q * t1
        if i == 1:
            print('\t' * tabs + '\t1\tx\tx\t0\t1')
        else:
            print('\t' * tabs + f'\t{i}\t{q}\t{r}\t{t}\t{s}')
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
    if euclidean_alg_gcd(a, b) != 1:
        return -1
    m = eulers_phi(b)
    return a ** (m - 1) % b


def mod_inverse_euler_verbose(a: int, b: int) -> int:
    '''
    a * x ≣ 1 mod b
    '''
    if euclidean_alg_gcd(a, b) != 1:
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


def fast_inverse_mod(a: int, b: int) -> int:
    if a < 0:
        a = a % b
    gcd, inv, _ = extended_euclidean(a, b)
    return inv % b if gcd == 1 else -1


def inverse_mod(a: int, b: int) -> int:
    '''
    a * x ≣ 1 mod b
    '''
    if euclidean_alg_gcd(a, b) != 1:
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
def square_exponentiation(base: int, exponent: int, mod: int = None) -> int:
    if mod is None:
        return pow(base, exponent)
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


def chinese_remainder_theorem_verbose(x: int, d: int, p: int, q: int) -> int:
    # step 1a: x_p and x_q
    x_p = x % p
    print(f'\tx_p = {x} mod {p} = {x_p}')
    x_q = x % q
    print(f'\tx_q = {x} mod {q} = {x_q}')

    # step 1b: d_p and d_q
    d_p = d % (p - 1)
    print(f'\td_p = {d} mod {p - 1} = {d_p}')
    d_q = d % (q - 1)
    print(f'\td_q = {d} mod {q - 1} = {d_q}')

    # step 2: exponentiation
    y_p = square_exponentiation(x_p, d_p, p)
    print(f'\ty_p = {x_p}^{d_p} mod {p} = {y_p}')
    y_q = square_exponentiation(x_q, d_q, q)
    print(f'\ty_q = {x_q}^{d_q} mod {q} = {y_q}')

    # step 3: inverse transformation
    _, c_p, c_q = extended_euclidean(q, p)
    print(f'\tc_p = {q} * {c_p} mod {p} = {c_p % p}')
    print(f'\tc_q = {p} * {c_q} mod {q} = {c_q % q}')
    c_p, c_q = c_p % p, c_q % q

    # return result
    print(f'\tC = (({q} * {c_p}) * {y_p} + ({p} * {c_q}) * {y_q}) mod ({p} * {q}) = {((q * c_p) * y_p + (p * c_q) * y_q) % (p * q)}')
    return ((q * c_p) * y_p + (p * c_q) * y_q) % (p * q)


def crt_default(x: int, d: int, p: int, q: int) -> int:
    return (x ** d) % (p * q)


def crt_builtin(x: int, d: int, p: int, q: int) -> int:
    return pow(x, d, p * q)


def generate_prime_fermat(min_bits: int, prime_list: tuple[int] = None) -> int:
    start = 2 ** (min_bits - 1)
    stop = 2 ** min_bits - 1
    if prime_list is None:
        prime_list = []
    while True:
        prime = randrange(start, stop)
        if is_prime_fermat(prime):
            return prime


def generate_prime_miller(min_bits: int, prime_list: tuple[int] = None) -> int:
    start = 2 ** (min_bits - 1)
    stop = 2 ** min_bits
    if prime_list is None:
        prime_list = []
    while True:
        prime = randrange(start, stop)
        if is_prime_fermat(prime):
            return prime


def generate_rsa_key_pair(bits: int = 1024):
    p = generate_prime_miller(bits // 2)
    q = generate_prime_miller(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = choice([x for x in range(2, 100) if euclidean_alg_gcd(x, phi) == 1])
    d = fast_inverse_mod(e, phi)
    return (e, n), (d, p, q)


def generate_rsa_key_pair_verbose(bits: int = 1024):
    print(f'Generating RSA key pair with {bits} bits...')
    print('\tGenerating p... ', end='')
    p = generate_prime_miller(bits // 2)
    print('done.')
    print('\tGenerating q... ', end='')
    q = generate_prime_miller(bits // 2)
    print('done.')
    n = p * q
    print(f'\tn = {str(n)[:5]}...{str(n)[-5:]}')
    phi = (p - 1) * (q - 1)
    print(f'\tφ(n) = {str(phi)[:5]}...{str(phi)[-5:]}')
    e = choice([x for x in range(2, 20) if euclidean_alg_gcd(x, phi) == 1])
    print(f'\te = {e}')
    _, d, _ = extended_euclidean(e, phi)
    print(f'\td = {str(d)[:5]}...{str(d)[-5:]}')
    return (e, n), (d, p, q)


def rsa_encrypt_base(message: str | int, key: tuple[int, int], char_size: int = 8) -> str | int:
    e, n = key
    total = string_to_number(message, char_size) if isinstance(message, str) else message
    return str(square_exponentiation(total, e, n)) if isinstance(message, str) else square_exponentiation(total, e, n)


def rsa_encrypt_base_verbose(message: str | int, key: tuple[int, int], char_size: int = 8) -> str | int:
    e, n = key
    print(f'\te={e}, n={n}')
    total = string_to_number(message, char_size) if isinstance(message, str) else message
    print(f'\tM = {total}')
    print(f'\tC = {total}^{e} mod {n}')
    print(f'\tC = {square_exponentiation(total, e, n)}')
    return str(square_exponentiation(total, e, n)) if isinstance(message, str) else square_exponentiation(total, e, n)


def rsa_decrypt_base(cipher: str | int, key: tuple[int, int, int], ret_string: bool = True, char_size: int = 8) -> str | int:
    d, p, q = key
    total = chinese_remainder_theorem(int(cipher), d, p, q)
    if not ret_string:
        return total
    return number_to_string(total, char_size)


def get_primitive_roots(p: int) -> int:
    if p == 2:
        return 1
    roots = []
    prime_factors = prime_factors_brents(p - 1)
    for g in range(2, p):
        if all(square_exponentiation(g, (p - 1) // prime, p) != 1 for prime in prime_factors):
            roots.append(g)
    return roots


def get_a_primitive_root(p: int) -> int:
    return choice(get_primitive_roots(p))


def optimal_asymmetric_encryption_padding(message: str | int, seed: str = None, ret_string: bool = False) -> tuple[tuple[int, int, int], str | int]:
    binary = bin(message)[2:] if isinstance(message, int) else ''.join([str(bit) for bit in string_to_bits(message)])
    message_hash = bin(abs(hash(message)))[2:]
    padding = bin(69)[2:]
    datablock = message_hash + padding + binary
    if seed is None:
        seed = ''.join([bit for i, bit in enumerate(binary) if not i % 3 and not i % 5])
    elif isinstance(seed, str):
        seed = ''.join([str(bit) for bit in string_to_bits(seed)])
    if len(seed) < 5:
        seed += bin(69)[2:]
    mgf_seed = lsfr(len(seed), [2, 3, 5], seed, len(datablock) + 1)
    masked_datablock = ''.join([str(int(bit) ^ next(mgf_seed)) for bit in datablock])
    mgf_db = lsfr(len(masked_datablock[:7]), [1, 2, 4], masked_datablock[:7], len(seed) + 1)
    masked_seed = ''.join([str(int(bit) ^ next(mgf_db)) for bit in seed])
    encoded_block = masked_seed + masked_datablock
    return (len(encoded_block), len(seed), len(padding), len(message_hash)), number_to_string(int(encoded_block, 2)) if ret_string else int(encoded_block, 2)


def optimal_asymmetric_encryption_unpadding(message: str | int, encoded_block_len: int, seed_len: int, padding_len: int, hash_length: int, ret_string: bool = True):
    encoded_message = bin(message)[2:].zfill(encoded_block_len) if isinstance(message, int) else ''.join([str(bit) for bit in string_to_bits(message)])
    masked_seed, masked_db = encoded_message[:seed_len], encoded_message[seed_len:]
    mgf_db = lsfr(len(masked_db[:7]), [1, 2, 4], masked_db[:7], seed_len + 1)
    seed = ''.join([str(int(bit) ^ next(mgf_db)) for bit in masked_seed])
    mgf_seed = lsfr(len(seed), [2, 3, 5], seed, len(masked_db) + 1)
    datablock = ''.join([str(int(bit) ^ next(mgf_seed)) for bit in masked_db])
    message = int(datablock[hash_length + padding_len:], 2)
    return (number_to_string(message), number_to_string(int(seed, 2))) if ret_string else (message, seed)


def generate_diffie_hellman_keys(q: int = None, alpha: int = None, xa: int = None, xb: int = None, bit_size: int = 1024) -> tuple[tuple, int]:
    # Domain variables
    if not q:
        q = generate_prime_miller(bit_size)

    if not alpha:
        alpha = get_a_primitive_root(q)

    # Party 1 variables
    if not xa:
        xa = randrange(2, q - 1)
    ya = square_exponentiation(alpha, xa, q)

    # Party 2 variables
    if not xb:
        xb = randrange(2, q - 1)
    yb = square_exponentiation(alpha, xb, q)

    # generate shared key
    ka = square_exponentiation(yb, xa, q)
    kb = square_exponentiation(ya, xb, q)

    assert ka == kb
    return (alpha, q, ya, yb), ka


def generate_diffie_hellman_keys_verbose(q: int = None, alpha: int = None, xa: int = None, xb: int = None, bit_size: int = 1024) -> tuple[tuple, int]:
    # Domain variables
    if not q:
        q = generate_prime_miller(bit_size)

    if not alpha:
        alpha = get_a_primitive_root(q)

    print(f'\tq={q}, ɑ={alpha}')

    # Party 1 variables
    if not xa:
        xa = randrange(2, q - 1)
    ya = square_exponentiation_verbose(alpha, xa, q)
    print(f'\txa={xa}, ya={ya}')

    # Party 2 variables
    if not xb:
        xb = randrange(2, q - 1)
    yb = square_exponentiation_verbose(alpha, xb, q)
    print(f'\txb={xb}, yb={yb}')

    # generate shared key
    ka = square_exponentiation_verbose(yb, xa, q)
    kb = square_exponentiation_verbose(ya, xb, q)
    print(f'\tka={ka}, kb={kb}')
    assert ka == kb
    return (alpha, q, ya, yb), ka


def generate_el_gemal(q: int = None, alpha: int = None, xb: int = None, bit_size: int = 1024):
    if not q:
        q = generate_prime_miller(bit_size)
    if not alpha:
        alpha = get_a_primitive_root(q)

    if not xb:
        xb = randrange(2, q - 1)
    yb = square_exponentiation(alpha, xb, q)
    return (alpha, q, yb), xb


def el_gemal_encrypt(message: str | int, key: tuple[int, int, int], a: int = None, char_size: int = 8) -> str | int:
    alpha, q, yb = key
    if isinstance(message, str):
        message = string_to_number(message, char_size)

    if not a:
        a = randrange(2, q - 1)
    ya = square_exponentiation(alpha, a, q)
    k = square_exponentiation(yb, a, q)
    c = (message * k) % q
    return (ya, c) if isinstance(message, int) else f'{ya},{c}'


def el_gemal_decrypt(cipher: str | int, key: tuple[int, int, int], char_size: int = 8) -> str | int:
    _, q, xb = key
    if isinstance(cipher, str):
        ya, c = map(int, cipher.split(','))
    else:
        ya, c = cipher
    k = square_exponentiation(ya, xb, q)
    _, m, _ = extended_euclidean(k, q)
    return c * m % q


def rsa_encrypt(message: str | int, key: tuple[int, int], char_size: int = 8) -> str | int:
    e, n = key
    total = string_to_number(message, char_size) if isinstance(message, str) else message
    padding_key, padded_message = optimal_asymmetric_encryption_padding(total)
    total = padded_message % n
    return padding_key, square_exponentiation(total % n, e, n)


def rsa_decrypt(cipher: str | int, padding_key: tuple[int, int, int], key: tuple[int, int, int], ret_string: bool = True, char_size: int = 8) -> str | int:
    d, p, q = key
    cipher = string_to_number(cipher, char_size) if isinstance(cipher, str) else cipher
    total = chinese_remainder_theorem(cipher, d, p, q)
    total = optimal_asymmetric_encryption_unpadding(total, *padding_key, ret_string=False)
    if not ret_string:
        return total
    return number_to_string(total, char_size)


def legendre_symbol(a: int, p: int) -> int:
    ls = square_exponentiation(a, (p - 1) // 2, p)
    if ls == p - 1:
        return -1
    return ls


def tonelli_shanks(n, p):
    if legendre_symbol(n, p) != 1:
        return None

    # Step 1: Factor p - 1 as 2^s * t
    s = 0
    q = p - 1
    while q % 2 == 0:
        q //= 2
        s += 1

    # Step 2: Find a quadratic non-residue z
    z = 1
    while legendre_symbol(z, p) != -1:
        z += 1

    # Step 3: Initialize variables
    m = s
    c = square_exponentiation(z, q, p)
    t = square_exponentiation(n, q, p)
    r = square_exponentiation(n, (q + 1) // 2, p)

    # Step 4: Loop until r^2 = n (mod p)
    while True:
        if t == 1:
            return r

        i = 0
        while square_exponentiation(t, 2**i, p) != 1:
            i += 1

        b = square_exponentiation(c, 2**(m - i - 1), p)
        m = i
        b_sq = (b * b)
        c = b_sq % p
        t = (t * b_sq) % p
        r = (r * b) % p


class Point:
    INF = (float('inf'), float('inf'))

    def __init__(self, x: int | tuple, y: int = None) -> None:
        if isinstance(x, tuple):
            x, y = x
        self.x = x
        self.y = y

    def __str__(self) -> str:
        return f"({self.x}, {self.y})"

    def __repr__(self) -> str:
        return f"({self.x}, {self.y})"

    def __eq__(self, other) -> bool:
        if isinstance(other, Point):
            return self.x == other.x and self.y == other.y
        if isinstance(other, tuple):
            return self.x == other[0] and self.y == other[1]
        return False

    def __hash__(self):
        return hash((self.x, self.y))

    def copy(self):
        return Point(int(self.x), int(self.y))


class EllipticCurve:
    def __init__(self, p: int, a: int, b: int) -> None:
        self.__p = p
        self.__a = a
        self.__b = b
        self.__points = set()
        self.__order = 0
        self.__generator = None

        if (4 * (a ** 3) + 27 * (b ** 2)) % p == 0:
            raise ValueError("This curve is singular")

    def __str__(self) -> str:
        ax = (f'{self.__a}x + ' if self.__a != 1 else 'x + ') if self.__a >= 1 else ''
        b = str(self.__b) if self.__b >= 1 else ''
        return f"y² = x³ + {ax}{b} (mod {self.__p})"

    def __repr__(self) -> str:
        ax = (f'{self.__a}x + ' if self.__a != 1 else 'x + ') if self.__a >= 1 else ''
        b = str(self.__b) if self.__b >= 1 else ''
        return f"y² = x³ + {ax}{b} (mod {self.__p})"

    @cache
    def add_points(self, p1, p2) -> Point:
        if p1 == Point.INF:
            return p2
        if p2 == Point.INF:
            return p1

        s = 0
        if p1.x != p2.x:
            s = (((p1.y - p2.y) % self.__p) * (fast_inverse_mod(p1.x - p2.x % self.__p, self.__p) % self.__p)) % self.__p
        else:
            if p1.y != p2.y:
                return Point(Point.INF)
            if p1.y == 0:
                return Point(Point.INF)
            s = ((((3 * (p1.x ** 2)) + self.__a) % self.__p) * fast_inverse_mod((2 * p1.y), self.__p)) % self.__p
        x3 = ((s ** 2) - p1.x - p2.x) % self.__p
        y3 = (s * (p1.x - x3) - p1.y) % self.__p
        return Point(x3, y3)

    @cache
    def multiply_point(self, p: Point, n: int) -> Point:
        if n == 0:
            return Point.INF
        if n == 1:
            return p

        q = p.copy()
        exponent = [int(x) for x in bin(n)[3:]]
        for h in exponent:
            q = self.add_points(q, q)
            if h == 1:
                q = self.add_points(q, p)
        return q

    def get_order_naive(self):
        if self.__order:
            return self.__order
        points = self.get_points_naive()
        return len(points)

    def get_points_naive(self):
        if len(self.__points) > 0:
            return self.__points
        points = [Point(x, y) for x in range(self.__p) for y in range(self.__p) if (y ** 2) % self.__p == (x ** 3 + self.__a * x + self.__b) % self.__p]
        self.__order = len(points) + 1
        self.__points = points
        # xis = []
        # yis = []
        # for x in range(self.__p):
        #     y_sqrd = (x ** 3 + self.__a * x + self.__b) % self.__p
        #     y = x
        #     xis.append([x, y_sqrd])
        #     yis.append([y, y ** 2 % self.__p])
        # points = set([Point(x[0], y[1]) for x in xis for y in yis if x[1] == y[1]])
        # self.__points = sorted(list(points), key=lambda point: point.x * self.__p + point.y) + [Point(Point.INF)]
        # self.__order = len(self.__points)
        return self.__points

    def get_generators_naive(self):
        points = list(self.get_points_naive())
        self.__order = len(points)
        gens = []
        for point in points[:-1]:
            i = 2
            while self.multiply_point(point, i) != Point.INF:
                p = self.multiply_point(point, i)
                print(f"{point} * {i} = {p}, {self.__order}, {self.__p}")
                i += 1
            if i == self.__order:
                gens.append(point)
        # print(f'{((self.__p) + 1) - (int((2 * self.__p ** 0.5)))} <= N <= {(self.__p + 1) + int((2 * self.__p ** 0.5) + 1)}')
        return gens

    def get_first_generator_naive(self):
        points = [Point(x, y) for x in range(2 * int(self.__p ** 0.5 + 1)) for y in range(2 * int(self.__p ** 0.5 + 1)) if (y ** 2) % self.__p == (x ** 3 + self.__a * x + self.__b) % self.__p]
        order_range = range((self.__p + 1) - int((2 * self.__p ** 0.5)), (self.__p + 1) + int((2 * self.__p ** 0.5) + 1))
        for point in points:
            i = 2
            while self.multiply_point(point, i) != Point.INF:
                i += 1
            if i in order_range:
                # print(self)
                # print(f'{(self.__p + 1) - int((2 * self.__p ** 0.5) + 1)} <= N <= {(self.__p + 1) + int((2 * self.__p ** 0.5) + 1)}')
                return point
        return None


def diffie_hellman_kex_ec(a: int = None, b: int = None, bit_size: int = 16) -> tuple[Point, int]:
    p, ec, P = None, None, None
    while True:
        try:
            p = generate_prime_miller(bit_size)
            print(f'p = {p}')
            ec = EllipticCurve(p, 0, randint(2, p - 1))
            print(f'ec = {ec}')
            P = ec.get_first_generator_naive()
            print(f'P = {P}')
            if P is not None:
                break
        except ValueError:
            pass

    order = (p + 1) - int((2 * p ** 0.5))

    if a is None and b is None:
        a = randint(2, p - 1)
        b = randint(2, p - 1)

    while True:
        A = ec.multiply_point(P, a)
        print(f'A = {A}')
        B = ec.multiply_point(P, b)
        print(f'B = {B}')
        Ka = ec.multiply_point(B, a)
        Kb = ec.multiply_point(A, b)
        if Ka == Point.INF or Kb == Point.INF or Ka != Kb:
            a = randint(2, order - 1)
            b = randint(2, order - 1)
        else:
            break
    assert Ka == Kb

    return (ec, P), (a, b), Ka


def DSA():
    pass


def ECDSA():
    pass


def shawe_taylor_random_prime_routine(length, seed):
    skip_to_14 = False
    if length < 2:
        raise ValueError('length must be greater than 1')
    if length >= 33:
        skip_to_14 = True

    if not skip_to_14:
        prime_seed = seed
        prime_gen_counter = 0
        while True:
            c = int.from_bytes(sha256(str(prime_seed).encode()).digest()) ^ int.from_bytes(sha256(str(prime_seed + 1).encode()).digest())
            c = (2 ** (length - 1)) + (c % (2 ** (length - 1) - 1))
            c = (2 * (c // 2)) + 1
            prime_gen_counter += 1
            prime_seed += 2
            if is_prime_default(c):
                prime = c
                return prime, prime_seed, prime_gen_counter
            if prime_gen_counter > 4 * length:
                return 0, 0, 0
            break

    c0, prime_seed, prime_gen_counter = shawe_taylor_random_prime_routine(length // 2 + 2, seed)
    if c0 == 0 and prime_seed == 0 and prime_gen_counter == 0:
        return 0, 0, 0

    iterations = int(length / 256)
    old_counter = prime_gen_counter

    x = 0
    for i in range(iterations):
        x += int.from_bytes(sha256(str(prime_seed + i).encode()).digest()) * (2 ** (i * 256))

    prime_seed += iterations + 1
    x = 2 ** (length - 1) + (x % (2 ** (length - 1)))
    t = x // (2 * c0) + 1
    while True:
        if 2 * t * c0 + 1 > 2 ** length:
            t = 2 ** (length - 1) // (2 * c0)

        c = 2 * t * c0 + 1
        prime_gen_counter += 1

        a = 0
        for i in range(iterations):
            a += int.from_bytes(sha256(str(prime_seed + i).encode()).digest()) * (2 ** (i * 256))

        prime_seed += iterations + 1
        a = 2 + (a % (c - 3))
        z = square_exponentiation(a, 2 * t, c)
        if euclidean_alg_gcd(z - 1, c) == 1 and square_exponentiation(z, c0, c) == 1:
            prime = c
            return prime, prime_seed, prime_gen_counter
        if prime_gen_counter > old_counter + 4 * length:
            return 0, 0, 0
        t += 1


def provable_prime_constructor(L, N1, N2, firstseed, e):
    p1 = None
    p2 = None
    p0seed = None
    p2seed = None
    if N1 == 1:
        p1 = 1
        p2seed = firstseed
    else:
        p1, p2seed, _ = shawe_taylor_random_prime_routine(N1, firstseed)
        if p1 == 0 and p2 == 0:
            return 0, 0, 0, 0

    if N2 == 1:
        p2 = 1
        p0seed = firstseed
    else:
        p2, p0seed, _ = shawe_taylor_random_prime_routine(N2, p2seed)
        if p2 == 0 and p0seed == 0:
            return 0, 0, 0, 0

    p0, pseed, _ = shawe_taylor_random_prime_routine(L // 2 + 2, p0seed)
    if p2 == 0 and p0seed == 0:
        return 0, 0, 0, 0

    if euclidean_alg_gcd(p0 * p1, p2) != 1:
        return 0, 0, 0, 0

    iterations = L // 256
    pgen_counter = 0

    x = 0
    for i in range(iterations):
        x += int.from_bytes(sha256(str(pseed + i).encode()).digest()) * (2 ** (i * 256))
    pseed += iterations + 1
    x = int((2 ** 0.5) * (2 ** (L - 1))) + (x % ((2 ** L) - int(2 ** (L - 1))))

    y = fast_inverse_mod(p0 * p1, p2)
    if p0 * p1 * p2 == 0:
        return 0, 0, 0, 0

    t = (((2 * y * p0 * p1) + x) // (2 * p0 * p1 * p2)) + 1
    while True:
        if (2 * (t * p2 - y) * p0 * p1 + 1) > 2 ** L:
            t = ((2 * y * p0 * p1 + int(2 ** (L - 1))) // (2 * p0 * p1 * p2)) + 1

        p = 2 * (t * p2 - y) * p0 * p1 + 1
        pgen_counter += 1
        if euclidean_alg_gcd(p - 1, e) == 1:
            a = 0
            for i in range(iterations):
                a += int.from_bytes(sha256(str(pseed + i).encode()).digest()) * (2 ** (i * 256))
            pseed += iterations + 1
            a = 2 + (a % (p - 3))
            z = square_exponentiation(a, 2 * (t * p2 - y) * p1, p)
            if euclidean_alg_gcd(z - 1, p) == 1 and square_exponentiation(z, p0, p) == 1:
                return p, p1, p2, pseed

        if pgen_counter > 5 * L:
            return 0, 0, 0, 0
        t += 1

        return p, p1, p2, pseed


def get_p_q(nlen, e, seed):
    working_seed = seed

    L = nlen // 2
    N1 = 1
    N2 = 1

    p = 0
    while p == 0:
        p, _, _, pseed = provable_prime_constructor(L, N1, N2, working_seed, e)
        working_seed = pseed

    q = 0
    while abs(p - q) <= 2 ** (L - 100) or q == 0:
        q, _, _, qseed = provable_prime_constructor(L, N1, N2, working_seed, e)
        working_seed = qseed
    return p, q


def drbg_cycle(block_1: list[int], block_2: list[int], block_3: list[int]):
    b_1o_pos = 65 // 93 * len(block_1)
    b_2o_pos = 68 // 84 * len(block_2)
    b_3o_pos = 67 // 111 * len(block_3)

    b_1i1_pos = 68 // 93 * len(block_1) + 1
    b_1i2_pos = len(block_3) - 3
    b_1i3_pos = b_1i2_pos + 1

    b_2i1_pos = 77 // 84 * len(block_2)
    b_2i2_pos = len(block_1) - 3
    b_2i3_pos = b_2i2_pos + 1

    b_3i1_pos = 88 // 111 * len(block_3) + 1
    b_3i2_pos = len(block_2) - 3
    b_3i3_pos = b_3i2_pos + 1

    b1_o = (block_1[-1] + block_1[b_1o_pos]) % 2
    b2_o = (block_2[-1] + block_2[b_2o_pos]) % 2
    b3_o = (block_3[-1] + block_3[b_3o_pos]) % 2

    b1_i = (block_1[b_1i1_pos] + (b3_o + (block_3[b_1i2_pos] & block_3[b_1i3_pos]))) % 2
    b2_i = (block_2[b_2i1_pos] + (block_1[b_2i2_pos] & block_1[b_2i3_pos])) % 2
    b3_i = (block_3[b_3i1_pos] + (block_2[b_3i2_pos] & block_2[b_3i3_pos])) % 2

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


def approved_drbg(entropy, nonce, security_requested: int = 2048):
    block_1 = [int(entropy[i]) if i < len(entropy) else 0 for i in range(int(31 * security_requested / 96))]
    block_2 = [int(nonce[i]) if i < len(nonce) else 0 for i in range(int(7 * security_requested / 24) + 1)]
    block_3 = [1 if i > 107 else 0 for i in range(int(37 * security_requested / 96))]

    # warm up
    for _ in range(4 * security_requested):
        block_1, block_2, block_3, _ = drbg_cycle(block_1, block_2, block_3)

    # generate output
    for _ in range(security_requested):
        block_1, block_2, block_3, zi = drbg_cycle(block_1, block_2, block_3)
        yield zi


def generate_random_bits(bits_requested: int):
    n_security = bits_requested + 256
    if n_security % 2 == 1:
        n_security += 1
    rand_bits = bin(SystemRandom().getrandbits(n_security + n_security // 2))[2:]
    seed, nonce = rand_bits[:n_security], rand_bits[n_security:]

    res = ''
    while True:
        drbg = approved_drbg(seed, nonce, n_security)
        for _ in range(n_security):
            res += str(next(drbg))
            if len(res) == bits_requested:
                return res
        nonce, seed = seed[n_security // 2:], res


def RSA(bit_len: int = 2048, e: int = 65537):
    # RSA SPECIFICATION REQUIREMENTS
    # RSA Private Key used to create Digital Signature
    #     - n: product of two primes p and q, could also be stored as p and q
    #     - e: public exponent
    #     - d: private exponent
    # RSA Public Key used to verify Digital Signature
    #     - n: product of two primes p and q
    #     - e: public exponent
    # p, q, d must be kept secret
    # n must be even bit length <= 2048
    # p and q must be equal bit len and half the bit len of n
    # p must be sqrt(2)(2^(n/2 - 1)) <= p <= 2^(n/2 - 1)
    # q must be sqrt(2)(2^(n/2 - 1)) <= q <= 2^(n/2 - 1)
    # |p - q| > 2^(n/2 - 100)
    # Approved hash functions must have >= security strength of n
    # e must be odd and 2^16 < e < 2^256 and must be selected before p, q
    # e may either be fixed or random
    # d must be positive and 2^(n/2) < d < LCM(p-1, q-1)
    # d = e^-1 mod LCM(p-1, q-1)
    # LCM(p-1, q-1) = phi(n) = (p-1)(q-1)
    # if d <= 2^(n/2) then select new p, q, d. new e is optional

    # p/q prime generation specifications
    # seed used for random number generation must have twice the security strength of n
    # SEED GENERATION
    #     - input: bit len of n
    #     - output: status, success or failure
    #     - output: seed, if failure, seed is 0
    #
    #     - if n bits not valid then return failure
    #     - return 2 * n bits from DRBG
    # doesnt work correctly.... p/q arent prime
    while True:
        if e is None:
            e = SystemRandom().randrange(2 ** 16 + 1, 2 ** 256, 2)
        seed = int(generate_random_bits(2 * bit_len), 2)
        p, q = get_p_q(bit_len, e, seed)
        n = p * q
        phi = (p - 1) * (q - 1)
        d = fast_inverse_mod(e, phi)
        if d != -1:
            return (e, n), (d, p, q)


def time_function(func, *args, **kwargs):
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
    pass


if __name__ == '__main__':
    main()
