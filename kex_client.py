import socket
from trivium_cipher import TriviumCipher, TriviumKey
from utils import EllipticCurve, Point, optimal_asymmetric_encryption_padding, optimal_asymmetric_encryption_unpadding, generate_prime_miller, string_to_number
from random import randint
import base64
import time


def default_parse(response):
    '''
    Default parser for responses.
    '''
    return response


def parse_pong(response):
    '''
    Parse a PONG response.
    '''
    start = float(response)
    stop = time.perf_counter()
    return f'latency: {stop - start:.3f} seconds.'


PARSE_DICT = {
    'PING': parse_pong
}

def parse_response(command, response) -> str:
    '''
    Parse a response from the server.
    '''
    return PARSE_DICT.get(command, default_parse)(response)


class Session:
    def __init__(self, client, conn):
        self.client = client
        self.conn = conn
        self.key = None
        self.seed = None
        self.__key_exchange()

    def __key_exchange(self):
        shared_secret = None
        while shared_secret is None or shared_secret == Point.INF:
            # Generate domain parameters
            p, ec_a, b, ec, P = None, 0, None, None, None
            while True:
                try:
                    p = generate_prime_miller(16)
                    ec_b = randint(2, p - 1)
                    ec = EllipticCurve(p, ec_a, ec_b)
                    P = ec.get_first_generator_naive()
                    if P is not None:
                        break
                except ValueError:
                    pass

            # Generate private and public keys
            b = randint(2, p - 1)
            B = ec.multiply_point(P, b)
            self.seed = B

            # Send public key
            domain_info = str(tuple([p, ec_a, ec_b, str(P).replace(' ', '')])).replace('\'', '')
            self.send('KEX', domain_info)

            # Receive public key
            seed, command, response = self.receive()
            if command != 'KEX' or response != 'FIN':
                self.close()
                return
            seed_tokens = seed[1:-1].split(',')
            A = Point(int(seed_tokens[0]), int(seed_tokens[1]))

            # Generate shared secret
            shared_secret = ec.multiply_point(A, b)
        self.key = (shared_secret.x, shared_secret.y)

    def send(self, command: str, args: str):
        '''
        Send a message to the client.
        '''
        message = f'{command} ' + args
        encoding_info, message = optimal_asymmetric_encryption_padding(message, str(self.seed).replace(' ', ''))
        if self.key is not None:
            key, nonce = self.key
            key = ('1' * 40) + bin(key)[2:].zfill(40)
            nonce = bin(nonce)[2:].zfill(40) + ('1' * 40)
            cipher = TriviumCipher(plain_text=str(message), key=TriviumKey(seed=key, nonce=nonce))
            message = int(cipher.encrypt(), 2)
        byte_num = message.to_bytes((message.bit_length() + 7) // 8, 'big')
        base64_str = base64.b64encode(byte_num).decode()
        encoding_info_str = str(encoding_info).replace(' ', '').replace('\'', '')
        self.conn.send(f'{encoding_info_str} {base64_str}'.encode())

    def receive(self):
        '''
        Receive a message from the server.
        '''
        raw = ''
        while not raw:
            raw = self.conn.recv(4096).decode()
        tokens = raw.split(' ')
        encoding_info_str, data = tokens[0], tokens[1]
        encoding_info = [int(val) for val in encoding_info_str[1:-1].split(',')]
        data = int.from_bytes(base64.b64decode(data), 'big')
        if self.key is not None:
            key, nonce = self.key
            key = ('1' * 40) + bin(key)[2:].zfill(40)
            nonce = bin(nonce)[2:].zfill(40) + ('1' * 40)
            cipher = TriviumCipher(cipher_text=bin(data)[2:], key=TriviumKey(seed=key, nonce=nonce))
            data = cipher.decrypt()
        if self.key is not None:
            data = int(data)
        message, seed = optimal_asymmetric_encryption_unpadding(data, *encoding_info)
        args = message.split(' ')
        command = args[0]
        message = ' '.join(args[1:])
        return seed, command, message

    def close(self):
        self.send('EXIT', 'NULL')
        self.conn.close()


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.session = None

    def run(self):
        try:
            self.conn.connect((self.host, self.port))
            print(f'Connected to server at {self.host}:{self.port}')
            print('Initializing key exchange...')
            self.session = Session(self, self.conn)
            print('Key exchange complete.\n')
            while True:
                inp = input('>> ').split(' ', 1)
                command = inp[0].upper()
                args = inp[1] if len(inp) > 1 else 'NULL'
                self.session.send(command, args)
                if command == 'EXIT':
                    return
                _, _, response = self.session.receive()
                print(parse_response(command, response))
        except (Exception, KeyboardInterrupt) as e:
            self.close()
            print('An unknown error occurred:', e)
            return

    def close(self):
        if self.session is not None:
            self.session.close()
        else:
            self.conn.close()


def main():
    host = '127.0.0.1'
    port = 55000
    client = Client(host, port)
    client.run()


if __name__ == '__main__':
    main()
