



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
import ledger.utils as ledger_utils
from addressing import addresser
from db import accounts_query


import coloredlogs, logging
import random
import smtplib
import boto3

coloredlogs.install()



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
    key_index = ledger_utils.generate_key_index(account.create_asset_idxs)
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

async def set_password(app, account, password, pancard=None):
    """
    Args:
        app(dict): config of the appliccation
        password(str): password put in by the user
        account(dict) will have the following keys

            user_id(str):
                user_id of the user
            role(str):
                could be anything from ["Admin", "USER", "CONSUMER", "LAB"]
            flt_acc_idxs(list):
                array of ndexes on which float_account trasactions were made
            child_acc_idxs(list):
                only non empty for MASTER and LAB, it will have all the indxs
                for which float_account transactions were made and will be the
                addresses of several people within the same organization
            share_asset_idxs(list):
                    indexes on which shared asset were made
            create_asset_idxs(list):
                    indexes on which create asset were made
            recvd_asset_idxs(list):
                    indexes on which recvd assets were made
            pancard(string):
                    pancard of the user
            admin_zero_pub(str):
                    zero public key of the QCI
            phone_number(str):
                    phone number of the users
            email(str):
                    email of the user
            encrypted_admin_mnemonic(hex encoded str):
                    mnemonic encrypted with QCI ZERO PUB
            acc_mstr_pub(str):
                    Master public key of the user
            acc_zero_pub(str):
                    Zero public key of the user
            transaction_id
            batch_id
            parent_idx
            parent_pub
            parent_role
            parent_zero_pub
            acc_master_pub
    """
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

    if pancard:
        account.update({"pancard": pancard})
    account.update({"password": h_password,
                    "salt": salt,
                    "encrypted_mnemonic": encrypted_mnemonic
    })
    return mnemonic, account

async def new_account(app, pancard, phone_number, email, role, \
                    gst_number, tan_number, org_name):
    """
    This method will be used to generate new mnemonic data when
    any parent wants to upload some data on the basis of
    just phone_number and pancard, The account is not claimed yet

    """
    if role not in app.config.ALLOWED_ROLES:
        raise ApiInternalError("Invalid role defined for the user")

    user_id = str(uuid.uuid4())

    if role != "ADMIN":
        master_pub, master_priv, zero_pub, zero_priv, mnemonic = await\
            generate_mnemonic(app.config.GOAPI_URL)
        admin_zero_pub = app.config.ADMIN_ZERO_PUB
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
            "claimed": False,
            "claimed_on": None,
        "role": role,
        "float_account_idxs": [],
        "share_asset_idxs": [],
        "create_asset_idxs": [],
        "receive_asset_idxs": [],
        "child_account_idxs": [],
        "closed": False,
        "pancard": pancard,
        "admin_zero_pub": admin_zero_pub,
        "phone_number": phone_number,
        "email": email,
        "gst_number": gst_number,
        "tan_number": tan_number,
        "org_name": org_name,
         "encrypted_admin_mnemonic": encrypted_admin_mnemonic,
         "acc_mstr_pub": master_pub,
         "acc_zero_pub": zero_pub}



async def sendEmail(app, user_id, email, validity):

    email_otp = random.randint(100000, 999999)

    try:
        s = smtplib.SMTP()
        s.connect('email-smtp.eu-west-1.amazonaws.com', 587)
        s.starttls()
        s.login('AKIAILISGU5WTFN5YHBA', 'AleyTERE8a/CuP23lTeQma0H9ti65xONxjhX66XoYae9')

    except Exception as e:
        logging.info("Somethign went wrong - %s" %e)

    msg = 'From: honey.ashthana@qcin.org\nSubject: Test email\n\nThis is test email\n\nCode is ' + str(email_otp)

    s.sendmail('honey.ashthana@qcin.org', email, msg)

    await accounts_query.insert_otps(app, "email", email_otp, user_id, email, validity)
    s.quit()

async def sendMessage(app, user_id, phone_number, validity):
    mobile_otp = random.randint(100000,999999)
    msg = 'Hi, %s this is your otp %s' %(user_id, mobile_otp)
    #client = boto3.client('sns','eu-west-1')

    client = boto3.client(
        "sns",
        aws_access_key_id='AKIAJV4L4DS37AP37LZQ',
        aws_secret_access_key='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',
        region_name="eu-west-1"
        )

    logging.info("This is the phone number on which OTP isbeing sent +91-%s"%phone_number)
    client.publish(PhoneNumber="91%s"%phone_number,
                Message=msg,
                 MessageAttributes={
                 'AWS.SNS.SMS.SMSType': {
                     'DataType': 'String',
                     'StringValue': 'Transactional'
                 }
             }
             )

    await accounts_query.insert_otps(app, "mobile", mobile_otp, user_id,  phone_number, validity)
