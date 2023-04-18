import socket
from trivium_cipher import TriviumCipher, TriviumKey
from utils import EllipticCurve, Point, optimal_asymmetric_encryption_padding, optimal_asymmetric_encryption_unpadding, generate_prime_miller, string_to_number
from random import randint
import threading
import base64
import time
import subprocess as sp


def close_session(session, args):
    session.close()


def ping_pong(session, args):
    stop = time.perf_counter()
    session.send('PONG', str(stop))


def sessions(session, args):
    message = 'Active sessions:\n'
    for key in session.server.sessions:
        message += f'\t{session.server.sessions[key]}\n'
    session.send('SESSIONS', message)


def send_help(session, args):
    message = 'Commands:\n\t' + \
        'banner - show welcome message\n\t' + \
        'echo - echo message\n\t' + \
        'exit - end session\n\t' + \
        'help - show this message' + \
        'ping - calculate latency\n\t' + \
        'sessions - show active sessions\n\t'
    session.send('HELP', message)


def banner(session, args):
    message = 'Welcome to the KEX server!'
    args = args.split(' ')
    session.send('BANNER', message)


INPUT_DICT = {
    'BANNER': banner,
    'ECHO': lambda session, args: session.send('ECHO', args),
    'EXIT': close_session,
    'HELP': send_help,
    'PING': ping_pong,
    'SESSIONS': sessions,
}


class Session:
    def __init__(self, num, server, conn, addr):
        self.server = server
        self.conn = conn
        self.addr = addr
        self.key = None
        self.seed = None
        self.__id = num
        self.__key_exchange()

    def __str__(self):
        return f'{self.__id} - {self.addr}'

    def __repr__(self):
        return f'{self.__id} - {self.addr}'

    def __key_exchange(self):
        seed, command, message = self.receive()
        if command != 'KEX':
            self.seed = seed
            self.send('ERR', 'Invalid command.')
            self.close()
            return
        seed_tokens = seed[1:-1].split(',')
        B = Point(int(seed_tokens[0]), int(seed_tokens[1]))
        domain_info = message[1:-1].split(', ')
        P = Point(tuple([int(x) for x in domain_info[3][1:-1].split(',')]))
        p, ec_a, ec_b = int(domain_info[0]), int(domain_info[1]), int(domain_info[2])
        ec = EllipticCurve(p, ec_a, ec_b)
        a = randint(2, p - 1)
        A = ec.multiply_point(P, a)
        self.seed = A
        self.send('KEX', 'FIN')
        shared_secret = ec.multiply_point(B, a)
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
        print(f'Client [{self.__id}] at {self.addr[0]}:{self.addr[1]} disconnected.')
        self.conn.close()


class Server:
    def __init__(self, host: str, port: int, max_sessions: int = 10) -> None:
        server = None
        self.host = host
        self.port = port
        while True:
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.bind((self.host, self.port))
                break
            except OSError:
                self.port += 1
        self.server = server
        server.listen(max_sessions)
        self.sessions = {}
        self.__id = 0

    def handle_client(self, session):
        while True:
            try:
                _, command, args = session.receive()
                print(f'Client {session.addr[0]}:{session.addr[1]} sent command {command} with args {args}.')
                if command not in INPUT_DICT:
                    session.send('ERR', 'Invalid command.')
                INPUT_DICT[command](session, args)
                if command == 'EXIT':
                    break
            except (Exception, KeyboardInterrupt) as e:
                raise e
                session.close()
                break

    def run(self):
        try:
            print(f'Listening for connections on port {self.port}...')
            while True:
                conn, addr = self.server.accept()
                print(f'Connected to client [{self.__id}] at {addr[0]}:{addr[1]}')
                session = Session(self.__id, self, conn, addr)
                print(f'Handshake with client [{self.__id}] complete.')
                threading.Thread(target=lambda: self.handle_client(session)).start()
                print(f'Client [{self.__id}] thread started.')
                self.sessions[self.__id] = session
                self.__id += 1
        except (Exception, KeyboardInterrupt) as e:
            raise e
            self.server.close()


def main():
    '''
    Start a server that listens for connections on port 55000.
    '''
    host = '127.0.0.1'
    port = 55000
    server = Server(host, port)
    server.run()


if __name__ == '__main__':
    main()
