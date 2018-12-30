


from encryption import key_derivations
from encryption.symmetric import aes_encrypt, aes_decrypt
from SSSA import sssa
import coloredlogs, logging
import binascii
from routes.resolve_account import ResolveAccount
coloredlogs.install()

def split_mnemonic(email, mnemonic, minimum_required, total_shares):
    """
    Derive an Scrypt key with the user's email with salt, this should be secure
    as email's are unique

    Now the key which is being generated, must be used to encrypt the mnemonic,
    this encrypted ciphertext must be appended with the tag and nonce,
    ciphertext must be hex encoded and then must be split into different shares

    Output:
        salt: bytes
        shares: list of str

    """
    key1, salt_one = key_derivations.generate_scrypt_key(
                                    email, 1, salt=None)

    ##Encypting mnemonic with AES key genearted from scrypt key
    ##generated from the email
    key2, salt_two = key_derivations.generate_scrypt_key(
                                key1, 1, salt=None)


    ciphertext, tag, nonce = aes_encrypt(key2, mnemonic)

    ##ciphertest must be appended with tag and nonce so that MAC can be checked
    ##while decryption
    ciphertext = b"".join([tag, ciphertext, nonce])

    ##hex encoding of ciphertext, the shamor secret will fail if its avoided
    hexlified_ciphertext = binascii.hexlify(ciphertext)

    sss = sssa()

    ##breaking hexlified_ciphertext with shamir secrets
    shares = sss.create(minimum_required, total_shares, hexlified_ciphertext)

    ##this salt will be kep in admin database, against this user mnemonic
    return salt_one, salt_two, shares

    #SecretSharer.split_secret("c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a", 2, 3)


def combine_mnemonic(email, shares, salt_one, salt_two):
    ##ARGs:
    ##      shares:str must be a list of shamir secrets,
    ##              must be minimum required when secrets were created
    ##generating scrypt key on the basis of email and salt


    key1, _ = key_derivations.generate_scrypt_key(
                                    email, 1, salt=salt_one)

    ##Encypting mnemonic with AES key genearted from scrypt key
    ##generated from the email
    key2, _ = key_derivations.generate_scrypt_key(
                                key1, 1, salt=salt_two)


    sss = sssa()
    ##Combining all the shamir secrets, this will fail if the minimum secrets
    ##requirement will not be fulfilled
    secret = sss.combine(shares)
    unhexlified_secret = binascii.unhexlify(secret)
    mnemonic = aes_decrypt(key2, unhexlified_secret)
    return mnemonic.decode()
