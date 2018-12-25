

from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from sanic.log import logger
import binascii
import bcrypt

KEY_LENGTH = 16
N = 2**16 ##meant for ram
R = 10
P = 10 ##meant for CPU, increase in this parameter means more CPU
        ##Is required to calculate the hash



def generate_random_salt(number_of_bytes):
    return get_random_bytes(number_of_bytes)



def generate_scrypt_key(password, num_keys, salt=None):
    ##return bytes of keys, returns list in case of keys > 1
    if not salt:
        salt = get_random_bytes(32)
    keys = scrypt(password,  salt, KEY_LENGTH, N, R, P, num_keys)
    return keys, salt



def generate_bcrypt(password):
    hashed =bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed


def check_bcrypt(password: str, hashed_password: str):
    if isinstance(password, str):
        password = password.encode()

    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode()

    if bcrypt.checkpw(password, hashed_password):
        return True
    return False
