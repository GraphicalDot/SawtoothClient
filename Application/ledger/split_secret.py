


from encryption import key_derivations
from encryption.symmetric import aes_encrypt, aes_decrypt
from SSSA import sssa
import coloredlogs, logging
import binascii
from routes.resolve_account import ResolveAccount
coloredlogs.install()

def split_secret(email, mnemonic, minimum_required, total_shares):
    keys, salt = key_derivations.generate_scrypt_key(
                                    email, 1, salt=None)

    ##Encypting mnemonic with AES key genearted from scrypt key
    ##generated from the email
    ciphertext, tag, nonce = aes_encrypt(keys, mnemonic)

    ##ciphertest must be appended with tag and nonce so that MAC can be checked
    ##while decryption
    ciphertext = b"".join([tag, ciphertext, nonce])

    ##hex encoding of ciphertext, the shamor secret will fail if its avoided
    hexlified_ciphertext = binascii.hexlify(ciphertext)

    sss = sssa()

    ##breaking hexlified_ciphertext with shamir secrets
    shares = sss.create(minimum_required, total_shares, hexlified_ciphertext)

    ##this salt will be kep in admin database, against this user mnemonic
    return salt, shares

    #SecretSharer.split_secret("c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a", 2, 3)


def combine_secret(email, shares, salt):
    ##ARGs:
    ##      shares:str must be a list of shamir secrets,
    ##              must be minimum required when secrets were created
    ##generating scrypt key on the basis of email and salt
    keys, _ = key_derivations.generate_scrypt_key(
                                    email, 1, salt=salt)

    sss = sssa()
    ##Combining all the shamir secrets, this will fail if the minimum secrets
    ##requirement will not be fulfilled
    secret = sss.combine(shares)
    unhexlified_secret = binascii.unhexlify(secret)
    mnemonic = aes_decrypt(keys, unhexlified_secret)
    return mnemonic.decode()
