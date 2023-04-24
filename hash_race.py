import time
from sip import sip13, sip24, sip35
from sha import sha2
from utils import number_to_string, generate_random_bits
from alive_progress import alive_bar

def hash_first_char(a_string: str) -> int:
    hash_code = 0
    if len(a_string) > 0:
        hash_code = ord(a_string[0])
    return hash_code


def hash_sum(a_string: str) -> int:
    hash_code = 0
    for ch in a_string:
        hash_code += ord(ch)
    return hash_code


def hash_positional_sum(a_string: str) -> int:
    hash_code = 0
    length = len(a_string)
    for index in range(length):
        hash_code += 31 ** (length - 1 - index) * ord(a_string[index])
    return hash_code


def build_collision_counter(hash_func, filename: str) -> tuple:
    collision_counter = {}
    items_hashed = 0
    total_time = 0
    with open(filename) as file:
        for line in file:
            items_hashed += 1
            val = line.encode()
            start = time.perf_counter()
            key = hash_func(val)
            stop = time.perf_counter()
            total_time += stop - start
            if key in collision_counter:
                collision_counter[key] += 1
            else:
                collision_counter[key] = 0
    return collision_counter, items_hashed, total_time


def get_collision(hash_func, out_len) -> tuple:
    data = int('1' * 2 ** (out_len // 8), 2)
    hashes = {}
    with alive_bar(2 ** (out_len // 2)) as bar:
        while True:
            val = number_to_string(data)
            hash_code = hash_func(val.encode())
            if hash_code in hashes:
                return hash_code, data, hashes[hash_code]
            else:
                hashes[hash_code] = [data, val]
            data += 1
            bar()


def hash_test(collision_counter: dict, items_hashed: int, speed: float, hash_func) -> None:
    maxload = 0
    total_col = 0
    for key in collision_counter:
        if collision_counter[key] > maxload:
            maxload = collision_counter[key]
        total_col += collision_counter[key]
    spreadness = len(collision_counter)
    total_collision_rate = str(round(total_col / items_hashed * 100, 2)) + "%"
    spreadness_rate = str(round(spreadness / items_hashed * 100, 2)) + " %"
    speed = str(round(speed, 2)) + " seconds"
    print("hash function:", hash_func.__name__)
    print("total collision rate:", total_collision_rate)
    print("maximum collisions:", maxload)
    print("spread:", spreadness_rate)
    print("speed:", speed)


def main():
    filename = 'data/long_line_words.txt'
    hashes = [hash, sip13, sip24, sip35]
    for _, hash_func in enumerate(hashes):
        collision_counter, items_hashed, total_time = build_collision_counter(hash_func, filename)
        hash_test(collision_counter, items_hashed, total_time, hash_func)
        print()
    # hashes = [hash_first_char, hash_sum, hash_positional_sum]
    # for hash_func in hashes:
    #     hash_value, v1, v2 = get_collision(hash_func, 16 + 2)
    #     print("collision found")
    #     print("hash function:", hash_func.__name__)
    #     print("hash value:", hash_value)
    #     print("v1:", v1)
    #     print("v2:", v2)
    #     print()

    # hashes = [hash]
    # for hash_func in hashes:
    #     hash_value, v1, v2 = get_collision(hash_func, 64)
    #     print("collision found")
    #     print("hash function:", hash_func.__name__)
    #     print("hash value:", hash_value)
    #     print("v1:", v1)
    #     print("v2:", v2)
    #     print()


if __name__ == '__main__':
    main()
