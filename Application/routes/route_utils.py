



from errors.errors import ApiBadRequest
from errors.errors import ApiInternalError
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import encryption.utils as encryption_utils
from encryption import key_derivations
from encryption import symmetric
import uuid
import binascii
from remotecalls.remote_calls import generate_mnemonic
from ledger import deserialize_state
from addressing import addresser
from db import accounts_query
import pytz
import datetime
import coloredlogs, logging
import random
import smtplib
import boto3

coloredlogs.install()

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



async def generate_asset_indexes(app, address):
    """
    Generate a new asset_owner index,
    An account also have an asset_owners_idxs to which this index will be updated
    address could be float_account or account address both will have
    """


    if addresser.address_is(address) == "FLOAT_ACCOUNT":
        ##Get data from the state corresponding to this user
        account = deserialize_state.deserialize_float_account(
                                                app.config.REST_API_URL, address)
        type = "FLOAT_ACCOUNT"
    else:
        account = deserialize_state.deserialize_account(
                                        app.config.REST_API_URL, address)
        type ="ACCOUNT"

    logging.info(f"This is the account {account} and type is {type}")
    key_index = generate_key_index(account.create_asset_idxs)
    return key_index



def validate_fields(required_fields, request_json):
    try:
        for field in required_fields:
            if request_json.get(field) is None:
                raise ApiBadRequest("{} is required".format(field))
    except (ValueError, AttributeError):
        raise ApiBadRequest("Improper JSON format")


async def user_mnemonic_frm_password(app, account, password):
    """
    ##should only be use with authorized decorator api, because then
    ##only the correctness of password will be checked
    Decrypt user_mnemonic from the password given by the user
    """
    salt = binascii.unhexlify(account["salt"])

    key, salt = key_derivations.generate_scrypt_key(password, 1, salt)

    encrypted_mnemonic = binascii.unhexlify(account["encrypted_mnemonic"])
    decrypted_mnemonic = symmetric.aes_decrypt(key, encrypted_mnemonic)
    return decrypted_mnemonic


async def set_change_password(app, account, new_password):
    if account["role"] != "ADMIN":
        mnemonic= encryption_utils.decrypt_mnemonic_privkey(
                                    account["encrypted_admin_mnemonic"],
                                    app.config.ADMIN_ZERO_PRIV)
    else:
        mnemonic = app.config.ADMIN_MNEMONIC

    key, salt = key_derivations.generate_scrypt_key(new_password, 1, None)
    ciphertext, tag, nonce  = symmetric.aes_encrypt(key, mnemonic.encode())
    ciphertext = b"".join([tag, ciphertext, nonce])
    ##The AES_GCM encrypted file content
    encrypted_mnemonic = binascii.hexlify(ciphertext).decode()

    salt = binascii.hexlify(salt).decode()

    h_password = key_derivations.generate_bcrypt(new_password.encode()).decode()

    return h_password, salt, encrypted_mnemonic

async def set_password(app, account=None, password=None):
    if not account:
            raise errors.CustomError("Account shouldnt be empty")

    if account["role"] != "ADMIN":

        mnemonic= encryption_utils.decrypt_mnemonic_privkey(
                                    account["encrypted_admin_mnemonic"],
                                    app.config.ADMIN_ZERO_PRIV)
    else:
        mnemonic = app.config.ADMIN_MNEMONIC

    key, salt = key_derivations.generate_scrypt_key(password, 1, None)
    ciphertext, tag, nonce  = symmetric.aes_encrypt(key, mnemonic.encode())
    ciphertext = b"".join([tag, ciphertext, nonce])
    ##The AES_GCM encrypted file content
    encrypted_mnemonic = binascii.hexlify(ciphertext).decode()

    salt = binascii.hexlify(salt).decode()

    h_password = key_derivations.generate_bcrypt(password.encode()).decode()

    account.update({"password": h_password,
                    "salt": salt,
                    "encrypted_mnemonic": encrypted_mnemonic
    })
    return mnemonic, account


async def new_account(app, pancard=None, phone_number=None, email=None, role=None, \
                    gst_number=None, tan_number=None, org_name=None):
    """
    This method will be used to generate new mnemonic data when
    any parent wants to upload some data on the basis of
    just phone_number and pancard, The account is not claimed yet

    """
    user_id = str(uuid.uuid4())

    if role != "ADMIN":
        master_pub, master_priv, zero_pub, zero_priv, mnemonic = await\
            generate_mnemonic(app.config.GOAPI_URL)
        encrypted_admin_mnemonic = encryption_utils.encrypt_mnemonic_pubkey(
                                                mnemonic, admin_zero_pub)
        _mnemonic= encryption_utils.decrypt_mnemonic_privkey(encrypted_admin_mnemonic,
                                        app.config.ADMIN_ZERO_PRIV)

    else:
            ##this implies ADMIN account is being created i.e QCI account
            admin_zero_pub = None
            email = app.config.ADMIN_EMAIL
            zero_pub = app.config.ADMIN_ZERO_PUB
            master_pub = None
            encrypted_admin_mnemonic= None

    return {"user_id": user_id,
            "role": role,
            "share_asset_idxs": [],
            "create_asset_idxs": [],
            "child_account_idxs": [],
            "share_secret_addresses":[],
            "receive_secret_idxs": [],
            "closed": False,
            "pancard": pancard,
            "phone_number": phone_number,
            "email": email,
            "gst_number": gst_number,
            "tan_number": tan_number,
            "org_name": org_name,
            "encrypted_admin_mnemonic": encrypted_admin_mnemonic,
            "acc_mstr_pub": master_pub,
            "acc_zero_pub": zero_pub}


async def new_user_account(app, pancard=None, phone_number=None, email=None,
                        role=None, first_name=None, last_name=None):
    """
    This method will be used to generate new mnemonic data when
    any parent wants to upload some data on the basis of
    just phone_number and pancard, The account is not claimed yet

    """
    user_id = str(uuid.uuid4())

    master_pub, master_priv, zero_pub, zero_priv, mnemonic = await\
        generate_mnemonic(app.config.GOAPI_URL)
    encrypted_admin_mnemonic = encryption_utils.encrypt_mnemonic_pubkey(
                                            mnemonic, app.config.ADMIN_ZERO_PUB)
    _mnemonic= encryption_utils.decrypt_mnemonic_privkey(encrypted_admin_mnemonic,
                                    app.config.ADMIN_ZERO_PRIV)


    return {"user_id": user_id,
            "first_name": first_name,
            "last_name": last_name,
            "role": role,
            "share_asset_idxs": [],
            "create_asset_idxs": [],
            "child_account_idxs": [],
            "share_secret_addresses":[],
            "receive_secret_idxs": [],
            "pancard": pancard,
            "phone_number": phone_number,
            "email": email,
            "encrypted_admin_mnemonic": encrypted_admin_mnemonic,
            "acc_mstr_pub": master_pub,
            "acc_zero_pub": zero_pub,
            "deactivate": False,
            "deactivate_on": None}







async def send_message(app, user_id, user_name, phone_number, validity):
    logging.info("SEnding message to user through SNS")
    mobile_otp = random.randint(100000, 999999)
    msg = 'Message from Remedium, \
        Hello %s, \
        This is your otp for forgot_password %s'%(user_name, mobile_otp)
    #client = boto3.client('sns','eu-west-1')

    client = boto3.client(
        "sns",
        aws_access_key_id='AKIAJE43I3IPMJHTEAEA',
        aws_secret_access_key='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',
        region_name="us-west-2"
        )

    logging.info("This is the phone number on which OTP isbeing sent +91-%s"%phone_number)
    client.publish(PhoneNumber="+91%s"%phone_number,
                Message=msg,
                 MessageAttributes={
                 'AWS.SNS.SMS.SMSType': {
                     'DataType': 'String',
                     'StringValue': 'Transactional'
                 }
             }
             )

    await accounts_query.insert_otps(app, "mobile", mobile_otp, user_id,  phone_number, validity)
