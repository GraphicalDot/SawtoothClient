



from Crypto.Random import get_random_bytes
import base64
import binascii
from SSSA import sssa
import random
from ecies import encrypt, decrypt
from Logging.clogging import logger
import hashlib
import coincurve
import coloredlogs, logging

coloredlogs.install()
import base64



def diffi_hellman(pub_key, priv_key):
    logging.info(f"This is the public_key in function {pub_key}")

    alice_coin_priv =  coincurve.PrivateKey.from_hex(priv_key)
    #bob_coin_priv = coincurve.PrivateKey.from_hex(bob_priv)
    pub = coincurve.PublicKey(pub_key)
    logging.info(f"This is the public_key after parsing {pub}")
    logging.info(f"This is the public_key after parsing {pub.public_key}")
    return binascii.hexlify(alice_coin_priv.ecdh(pub.public_key))



def pub_encrypt(text, public_key):
    try:
        return encrypt(public_key, text)
    except Exception as e:
        logger.error(f"While encrypting data with publickey{public_key} and data {text}is {e}")
        raise Exception("Couldnt encrypt with public key")

def priv_decrypt(cipher_text, private_key):
    try:
        return decrypt(private_key, cipher_text)
    except Exception as e:
        logger.error(f"While encrypting data with private key {private_key} and data {cipher_text} is {e}")
        raise Exception("Couldnt decrypt with private key")
