


from .key_derivations import generate_random_salt
from .symmetric import aes_encrypt
from .asymmetric import pub_encrypt
from .asymmetric import priv_decrypt
import binascii
import coloredlogs, logging
coloredlogs.install()

def encrypt_mnemonic_pubkey(mnemonic, pub_key):
    ##this encrypts the mnemonic witht he public key
    encrypted_mnemonic = pub_encrypt(mnemonic.encode(), pub_key)
    ##hex encoding aes key
    return binascii.hexlify(encrypted_mnemonic).decode()



def decrypt_mnemonic_privkey(encrypted_mnemonic, priv_key):
    ##this encrypts the mnemonic witht he public key
    logging.info(encrypted_mnemonic)
    mnemonic = binascii.unhexlify(encrypted_mnemonic)

    encrypted_mnemonic = priv_decrypt(mnemonic, priv_key)
    ##hex encoding aes key
    return encrypted_mnemonic.decode()



def encrypt_w_pubkey(mnemonic, pub_key):
    ##this encrypts the mnemonic witht he public key
    ##Mnemonic must be in bytes
    encrypted_mnemonic = pub_encrypt(mnemonic, pub_key)
    ##hex encoding aes key
    return binascii.hexlify(encrypted_mnemonic).decode()



def decrypt_w_privkey(encrypted_mnemonic, priv_key):
    ##this encrypts the mnemonic witht he public key
    mnemonic = binascii.unhexlify(encrypted_mnemonic)

    de_encrypted_mnemonic = priv_decrypt(mnemonic, priv_key)
    ##hex encoding aes key

    return de_encrypted_mnemonic
