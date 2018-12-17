


from .key_derivations import generate_random_salt
from .symmetric import aes_encrypt
from .asymmetric import pub_encrypt
from .asymmetric import priv_decrypt
import binascii
import coloredlogs, logging
coloredlogs.install()
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from sawtooth_signing import CryptoFactory
from sawtooth_signing import create_context



def create_signer(private_key_hex):
    private_key = Secp256k1PrivateKey.from_hex(private_key_hex)
    context = create_context('secp256k1')
    signer = CryptoFactory(context).new_signer(private_key)
    return signer




async def decrypted_user_mnemonic(app, encrypted_admin_mnemic, role):
    """
    return decrypted user mnemonic

    All the user menmonics for every tole except the "ADMIN" role is present in
    DB in two forms, One is encrypted with "ADMIN" ZERO key and the other is
    encrypted with the key generated from the user password with Scrypt alogirithm
    if user has already claimed his/her account
    """

    if role == "ADMIN":
        return app.config.ADMIN_MNEMONIC

    return decrypt_mnemonic_privkey(
                                            encrypted_admin_mnemic,
                                            app.config.ADMIN_ZERO_PRIV)






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




async def decrypt_keys_from_index(app, account, state_data):

    if account["role"] == "ADMIN":
        decrypted_mnemonic = app.config.ADMIN_MNEMONIC

    else:
        ##if we are getting float accounts for admin directly
        decrypted_mnemonic = await ledger_utils.decrypted_user_mnemonic(
            app,
            account["encrypted_admin_mnemonic"],
            account["role"])

    logging.info(f"Requester Mnemonic is {decrypted_mnemonic}")
    key_index = state_data["idx"]
    nth_keys = await remote_calls.key_index_keys(app, decrypted_mnemonic,
                                                        [key_index])

    nth_priv, nth_pub = nth_keys[str(key_index)]["private_key"], \
                        nth_keys[str(key_index)]["public_key"]


    if nth_pub != state_data["public"]:
        raise errors.CustomError("Unauthorized access of assset credentials")
    ## all the data being encrypted with user nth public key
    key = encryption_utils.decrypt_w_privkey(state_data["key"], nth_priv)
    url = encryption_utils.decrypt_w_privkey(state_data["url"], nth_priv)
    hex_file_data = await remote_calls.get_s3_link(url)
    encrypted_file_data = binascii.unhexlify(hex_file_data)


    file_data = symmetric.aes_decrypt(key, encrypted_file_data)

    return key, url, file_data


async def decrypt_file_data(encrypted_key, encrypted_url, file_hash, private_key):
    key = encryption_utils.decrypt_w_privkey(encrypted_key, private_key)
    url = encryption_utils.decrypt_w_privkey(encrypted_url, private_key)
    hex_file_data = await remote_calls.get_s3_link(url)
    encrypted_file_data = binascii.unhexlify(hex_file_data)


    file_data = symmetric.aes_decrypt(key, encrypted_file_data)

    return file_data


async def encrypt_file_data(user_id, public_key, config, file_data):
    key = symmetric.generate_aes_key(16)
    ciphertext, tag, nonce = symmetric.aes_encrypt(key, file_data["data"])
    ciphertext = b"".join([tag, ciphertext, nonce])
    ##The AES_GCM encrypted file content
    data = binascii.hexlify(ciphertext).decode()

    ##Encrypting AES key with the child public key
    encrypted_key = encryption_utils.encrypt_w_pubkey(key, public_key)
    asyncio.sleep(0.1)
    s3_key = amazon_s3.generate_s3_key(user_id, file_data["file_name"])
    s3_url = amazon_s3.store_s3(config,  s3_key, user_id, data)
    asyncio.sleep(0.1)
    encrypted_s3_url = encryption_utils.encrypt_w_pubkey(s3_url.encode(), public_key)
    return key, encrypted_key, s3_url, encrypted_s3_url



async def master_url_n_key(public_key, aes_key, url):
    """
    ##TODO test whether the key generated from qci private and user
    ## public key would be able tot decrypt the aes_key and s3_url
    ## and eventually the whole data for the user
    TODO: couldnt get diffihellman working, so right now just encrypting



    Users AES key and s3 url with QCI_PUB
    key = asymmetric.diffi_hellman(public_key, private_key)
    asyncio.sleep(.01)

    ciphertext, tag, nonce = symmetric.aes_encrypt(key, aes_key)
    ciphertext = b"".join([tag, ciphertext, nonce])
    ##The AES_GCM encrypted file content
    master_key = binascii.hexlify(ciphertext).decode()


    ciphertext, tag, nonce = symmetric.aes_encrypt(key, url)
    ciphertext = b"".join([tag, ciphertext, nonce])
    ##The AES_GCM encrypted file content
    master_url = binascii.hexlify(ciphertext).decode()
    return master_key, master_url
    """
    master_key = encryption_utils.encrypt_w_pubkey(aes_key, public_key)

    master_url = encryption_utils.encrypt_w_pubkey(url.encode(), public_key)
    return master_key, master_url
