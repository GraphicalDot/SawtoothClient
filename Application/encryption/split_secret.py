


from encryption import key_derivations
from encryption.symmetric import aes_encrypt, aes_decrypt
from SSSA import sssa
import coloredlogs, logging
import binascii
from routes.resolve_account import ResolveAccount
coloredlogs.install()

def split_mnemonic(key_salt_array, mnemonic, minimum_required, total_shares):
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

    #ciphertext, tag, nonce = aes_encrypt(key2, mnemonic)

    ##ciphertest must be appended with tag and nonce so that MAC can be checked
    ##while decryption
    #ciphertext = b"".join([tag, ciphertext, nonce])

    ##hex encoding of ciphertext, the shamor secret will fail if its avoided
    #hexlified_ciphertext = binascii.hexlify(ciphertext)

    sss = sssa()

    ##breaking hexlified_ciphertext with shamir secrets
    shares = sss.create(minimum_required, total_shares, mnemonic)

    ##this salt will be kep in admin database, against this user mnemonic
    new_list = []
    for ((key, salt), secret) in zip(key_salt_array, shares):
        _key, _salt = binascii.unhexlify(key), binascii.unhexlify(salt)
        ciphertext, tag, nonce = aes_encrypt(_key, secret)

        ##ciphertest must be appended with tag and nonce so that MAC can be checked
        ##while decryption
        ciphertext = b"".join([tag, ciphertext, nonce])

        ##hex encoding of ciphertext, the shamor secret will fail if its avoided
        hexlified_ciphertext = binascii.hexlify(ciphertext)
        new_list.append({"key": key, "salt": salt, "secret": binascii.hexlify(ciphertext)})

    return new_list

    #SecretSharer.split_secret("c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a", 2, 3)

def combine_mnemonic(secret_salt_array):
    ##ARGs:
    ##      shares:str must be a list of shamir secrets,
    ##              must be minimum required when secrets were created
    ##generating scrypt key on the basis of email and salt

    new_list = []
    for (key, salt, secret) in secret_salt_array:
        _key, _salt, _secret = binascii.unhexlify(key), binascii.unhexlify(salt),\
                    binascii.unhexlify(secret)
        decrypted_share = aes_decrypt(_key, _secret)

        ##ciphertest must be appended with tag and nonce so that MAC can be checked
        ##while decryption
        new_list.append(decrypted_share)
        ##hex encoding of ciphertext, the shamor secret will fail if its avoided
        #hexlified_ciphertext = binascii.hexlify(ciphertext)
        #new_list.append({"key": key, "salt": salt, "secret": ciphertext})


    sss = sssa()
    ##Combining all the shamir secrets, this will fail if the minimum secrets
    ##requirement will not be fulfilled
    mnemonic = sss.combine(new_list)
    return mnemonic
