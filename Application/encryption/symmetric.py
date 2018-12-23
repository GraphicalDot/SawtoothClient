

from Crypto.Cipher import AES

from Crypto.Random import get_random_bytes
import base64
import binascii
import random
import coloredlogs, logging
coloredlogs.install()

def generate_child_key_index():
    ##ideally it should be 2**32 -1
    return random.choice(range(1, 2**32-1))

def generate_aes_key(number_of_bytes):
    return get_random_bytes(number_of_bytes)



def aes_encrypt(key, file_bytes):
    ##The nonce and the tag generated will be exactly 16 bytes
    ##ciphertext, tag, nonce = aes_encrypt(key, file_bytes)
    ##ciphertext = b"".join([tag, ciphertext, nonce])
    ##The AES_GCM encrypted file content
    ##secret = binascii.hexlify(ciphertext)
    if isinstance(file_bytes, str):
        file_bytes = file_bytes.encode()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_bytes)
    nonce = cipher.nonce
    return ciphertext, tag, nonce


def aes_decrypt(key, ciphertext):
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode()
    tag, nonce = ciphertext[:16], ciphertext[-16:]

    cipher = AES.new(key, AES.MODE_GCM, nonce)
    decrypted_text = cipher.decrypt_and_verify(ciphertext[16:-16], tag)
    return decrypted_text



def base64decoding(b64_bytes):
    try:
        #the arg will be a base64 encoded string, it must be convcerted to bytes
        result = base64.b64decode(b64_bytes.encode())
    except Exception as e:
        print(e)
        raise Exception("Base64 encoding failed")
    return result




def recover_mnemonic(password, secrets):
    shares = []
    key = binascii.unhexlify(password)
    for secret in secrets:
        data = binascii.unhexlify(secret)
        nonce, tag = data[:12], data[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        shares.append(cipher.decrypt_and_verify(data[12:-16], tag))
    sss = sssa()
    mnemonic = sss.combine(shares)

    return mnemonic
