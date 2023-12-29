class OperationMode:
    '''
    Each Mode of Operation will have underlying cipher to encrypt/decrypt one block of data.
    Each Mode of Operation will have a padding scheme and some form of key schedule.
    '''
    def __init__(self, cipher):
        '''
        cipher will be some form of block cipher that can encrypt/decrypt one block of data.
            - cipher.encrypt(data: bytes, key: bytes) -> bytes
            - cipher.decrypt(data: bytes, key: bytes) -> bytes
        '''
        self.cipher = cipher

    def __pad(self):
        raise NotImplementedError

    def __unpad(self):
        raise NotImplementedError

    def __key_schedule(self):
        raise NotImplementedError

    def encrypt(self):
        raise NotImplementedError

    def decrypt(self):
        raise NotImplementedError


class ECB:
    '''
    Electrinic Code Book
    '''
    pass


class CBC:
    pass


class PCBC:
    pass


class CFB:
    pass


class OFB:
    pass


class CTR:
    pass


class GCM:
    pass
