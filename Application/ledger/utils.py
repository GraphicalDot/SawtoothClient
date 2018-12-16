

import random
from encryption import utils as encryption_utils
from sawtooth_signing import create_context
from sawtooth_signing import ParseError
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from sawtooth_signing import CryptoFactory

def create_signer(private_key_hex):
    private_key = Secp256k1PrivateKey.from_hex(private_key_hex)
    context = create_context('secp256k1')
    signer = CryptoFactory(context).new_signer(private_key)
    return signer


def indian_time_stamp():
    tz_kolkata = pytz.timezone('Asia/Kolkata')
    time_format = "%Y-%m-%d %H:%M:%S"
    naive_timestamp = datetime.datetime.now()
    aware_timestamp = tz_kolkata.localize(naive_timestamp)
    return aware_timestamp.strftime(time_format + " %Z%z")


def revoke_time_stamp(days=0, hours=0, minutes=0):
    tz_kolkata = pytz.timezone('Asia/Kolkata')
    time_format = "%Y-%m-%d %H:%M:%S"
    naive_timestamp = datetime.datetime.now()
    aware_timestamp = tz_kolkata.localize(naive_timestamp)

    ##This actually creates a new instance od datetime with Days and hours
    _future = datetime.timedelta(days=days, hours=hours, minutes=minutes)
    result = aware_timestamp + _future
    return result.timestamp()



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

    return encryption_utils.decrypt_mnemonic_privkey(
                                            encrypted_admin_mnemic,
                                            app.config.ADMIN_ZERO_PRIV)


async def generate_key_index(array):
    ##this will output the key from 1 to 2**32-1 which is not present in
    ## array, though the probability of thats happening is very very low as
    ## 2**32 is huge number, we still want to make sure that duplicate keys
    ## shouldnt exists in array
    key_index = random.randint(1, 2**32-1)
    if not array:
        return key_index
    while key_index in array:
        ##if the array is huge, it will get stuck
        await asyncio.sleep(.01)
        key_index = random.randint(1, 2**32-1)
    return key_index
