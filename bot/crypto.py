from cryptography.fernet import Fernet

from .config import SECRET


class Cipher(object):
    cipher = Fernet(SECRET)

    @classmethod
    def encrypt(cls, data):
        if not isinstance(data, bytes):
            data = bytes(data, 'utf8')
        return cls.cipher.encrypt(data)

    @classmethod
    def decrypt(cls, cipher_text):
        return cls.cipher.decrypt(cipher_text)
