
from errors.errors import ApiBadRequest, ApiInternalError
import pytz
from sanic.log import logger
import random
import datetime
import base64
import hashlib
import asyncio
from errors.errors import ApiInternalError
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from sawtooth_signing import CryptoFactory
from sawtooth_signing import create_context

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


def now_time_stamp():
    tz_kolkata = pytz.timezone('Asia/Kolkata')
    naive_timestamp = datetime.datetime.now()
    aware_timestamp = tz_kolkata.localize(naive_timestamp)
    return aware_timestamp.timestamp()



def revoke_time_stamp(days=0, hours=0, minutes=0):
    tz_kolkata = pytz.timezone('Asia/Kolkata')
    time_format = "%Y-%m-%d %H:%M:%S"
    naive_timestamp = datetime.datetime.now()
    aware_timestamp = tz_kolkata.localize(naive_timestamp)

    ##This actually creates a new instance od datetime with Days and hours
    _future = datetime.timedelta(days=days, hours=hours, minutes=minutes)
    result = aware_timestamp + _future
    return result.timestamp()



def base64decoding(file_bytes):
    try:
        return base64.b64decode(file_bytes)
    except Exception as e:
        raise ApiInternalError(e)


def check_hash(file_bytes, hash):
        calculated_hash = hashlib.sha224(file_bytes).hexdigest()
        if calculated_hash != hash:
            raise ApiBadRequest("File hash doesnt Match, Please send the right sha224 hash")
        return True




def validate_fields(required_fields, request_json):
    try:
        for field in required_fields:
            if request_json.get(field) is None:
                raise ApiBadRequest("{} is required".format(field))
    except (ValueError, AttributeError):
        raise ApiBadRequest("Improper JSON format")
