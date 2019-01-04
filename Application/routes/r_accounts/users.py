
##deals with the registration of the users

from sanic.request import RequestParameters
from .authorization import authorized
from routes.route_utils import validate_fields
from routes.route_utils import new_account
from routes.route_utils import set_password
from routes.route_utils import user_mnemonic_frm_password
from routes.route_utils import send_message, revoke_time_stamp, now_time_stamp

import hashlib
from db import accounts_query
import binascii
from sanic import response
from errors import errors
import db.accounts_query as accounts_db
from db.share_secret import get_addresses_on_ownership, update_mnemonic_encryption_salts
from db.db_secrets import get_addresses_on_ownership
import re
#from ledger.accounts.float_account.submit_float_account import submit_float_account
from ledger.accounts.organization_account.submit_organization_account import submit_organization_account
from ledger.accounts.user_account.submit_user_account import submit_user_account
from ledger.mnemonics.share_secrets.submit_share_secret import share_secret_batch_submit
from ledger.mnemonics.activate_secret.submit_activate_secret import activate_secret_batch_submit
from ledger.mnemonics.execute_share_secret.submit_execute_share_secret import submit_execute_share_secret
from ledger.mnemonics.receive_secrets.submit_receive_secret import submit_receive_secret

#from ledger.accounts.child_account.submit_child_account import submit_child_account
from remotecalls import remote_calls
from addressing import addresser, resolve_address
from encryption import utils as encryption_utils
from addressing import addresser
from encryption import asymmetric
from encryption import symmetric
from encryption import signatures
from encryption import key_derivations
import aiohttp
import asyncio
import datetime
import json
from encryption.split_secret import split_mnemonic, combine_mnemonic
from ledger import deserialize_state
from routes.resolve_account import ResolveAccount
from ledger import deserialize_state
from db.db_secrets import DBSecrets
import coloredlogs, verboselogs, logging
verboselogs.install()
coloredlogs.install()
logger = logging.getLogger(__name__)


from .send_email import ses_email

from ._format_api_result import format_get_organization_account,\
                                format_get_children,\
                                format_get_float_accounts



from sanic import Blueprint
USERS_BP = Blueprint('users', url_prefix='/users')




@USERS_BP.get('/index')
async def index(request):
    logging.info("Hey dude i came here")
    return request.app.config.jinja.render("index.html", request, greetings="Hello, sanic!")


@USERS_BP.get('/address')
async def get_address(request):
    """
    """
    address = request.args.get("address")
    logger.info(f"This is the address {address}")
    logger.debug(f"This is the address {address}")
    logger.error(f"This is the address {address}")
    logger.verbose(f"This is the address {address}")
    logger.critical(f"This is the address {address}")
    logger.warning(f"This is the address {address}")
    logger.success(f"This is the address {address}")
    logger.notice(f"This is the address {address}")

    if not address:
        raise errors.CustomError("address is required")

    instance = await resolve_address.ResolveAddress(address, request.app.config.REST_API_URL)

    if not instance.data:
        raise errors.ApiInternalError(f"State is not present on the blockchain for {address}")
    return response.json(
            {
            'error': False,
            'success': True,
            'message': f"{instance.type} type found",
            "data": instance.data,
            })







@USERS_BP.post('/registration')
async def register_user(request):
    """
    """
    required_fields = ["first_name", "last_name",
        "email", "password", "phone_number", "pancard"]

    validate_fields(required_fields, request.json)

    db_user = await accounts_query.find_on_key(request.app, "email", request.json["email"])

    if db_user:
        raise errors.CustomError("This email id has already been registered")

    if await accounts_query.find_on_key(request.app, "phone_number", request.json["phone_number"]):
        raise errors.CustomError("This phone_number has already been registered")

    required_pattern = re.compile('(?=.{6,})(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&*()])')
    if not required_pattern.match(request.json["password"]) or \
                        len(request.json["password"]) <= 8:
            raise errors.PasswordStrengthError()


    usr = await submit_user_account(request.app, pancard=request.json["pancard"], phone_number=request.json["phone_number"],
                        email=request.json["email"], role="USER",
                         password=request.json["password"], first_name=request.json["first_name"],
                        last_name=request.json["last_name"])

    return response.json(
            {
            'error': False,
            'success': True,
            "data": usr,
            })



@USERS_BP.get('/mnemonic')
@authorized()
async def get_mnemonic(request):
    """
    """
    pass



@USERS_BP.get('/all_share_secrets')
@authorized()
async def all_share_secrets(request, requester):
    """

    Result will have two keys,
    floated and received,
    floated will have all the shared_secret addresses that this user have floated
    and have his encryptes mnemonic distribution

    the received is all the shared_Secret_addresses that have shared with him,
    This information can only be pulled from database right now but
    sawtooth events will be used later
    """

    if requester["role"] == "USER":
        address = addresser.user_address(requester["acc_zero_pub"], 0)
        account = await deserialize_state.deserialize_user(request.app.config.REST_API_URL, address)

    else:
        logging.error("Not implemented yet")
        raise errors.ApiInternalError("This functionality is not implemented yet")



    logging.info(account)
    floated = account.get("share_secret_addresses")
    floated_result = []
    if floated:
        #implies that user has already have created shared_secrets contracts and
        ##this array have the addresses of the shared_secrets
        async with aiohttp.ClientSession() as session:
            floated_result= await asyncio.gather(*[
                deserialize_state.deserialize_share_secret(
                        request.app.config.REST_API_URL, address)
                    for address in floated
            ])

    received_result =await get_addresses_on_ownership(request.app, address)



    return response.json(
            {
            'error': False,
            'success': True,
            "data": {"floated": floated_result, "received": [received_result]},
            })


@USERS_BP.post('/recover_mnemonic')
@authorized()
async def recover_mnemonic(request, requester):
    """

    Result will have two keys,
    floated and received,
    floated will have all the shared_secret addresses that this user have floated
    and have his encryptes mnemonic distribution

    the received is all the shared_Secret_addresses that have shared with him,
    This information can only be pulled from database right now but
    sawtooth events will be used later
    """

    required_fields = ["password"]
    validate_fields(required_fields, request.json)
    if requester["role"] == "USER":
        address = addresser.user_address(requester["acc_zero_pub"], 0)
        account = await deserialize_state.deserialize_user(request.app.config.REST_API_URL, address)

    else:
        logging.error("Not implemented yet")
        raise errors.ApiInternalError("This functionality is not implemented yet")



    floated = account.get("share_secret_addresses")
    async with aiohttp.ClientSession() as session:
        share_secrets= await asyncio.gather(*[
            deserialize_state.deserialize_share_secret(
                    request.app.config.REST_API_URL, address)
                for address in floated
        ])

    ##TODO: if minimum _requires is satisfied
    db_instance = await DBSecrets(request.app, table_name="share_secret",
                                            array_name="share_secret_addresses",
                                            )

    new_list = []
    for share_secret in share_secrets:
        _d = await db_instance.get_fields( "share_secret_address",
                share_secret["address"],
                ["reset_key", "reset_bare_key", "reset_salt"])
        share_secret.update({"reset_key": _d["reset_key"],
            "reset_bare_key": _d["reset_bare_key"],
            "reset_salt": _d["reset_salt"]})

    #logging.info(new_list)
    logging.info(share_secrets)

    shares = {}
    for one in share_secrets:
        one_salt = binascii.unhexlify(one["reset_salt"])
        reset_secret = binascii.unhexlify(one["reset_secret"])
        scrypt_key, _ = key_derivations.generate_scrypt_key(request.json["password"], 1, salt=one_salt)
        logging.info(binascii.hexlify(scrypt_key))

        de_org_secret = symmetric.aes_decrypt(scrypt_key, reset_secret)
        logging.info(de_org_secret)
        shares.update({one["ownership"]: [de_org_secret]})

        #received_result =await get_addresses_on_ownership(request.app, address)
    logging.info(shares)

    address_salt_array = requester["org_mnemonic_encryption_salts"]

    final = []
    for e in address_salt_array:
        value = shares[e["receive_secret_address"]]
        value.append(e["salt"])
        final.append(value)

    logging.info(final)

    keys= await asyncio.gather(*[
                gateway_scrypt_keys(request.app, requester["email"], 1, salt)
                     for (secret, salt) in final
            ])

    pots = []
    for ((key, salt1),(secret, salt2)) in zip(keys, final):
        logging.info(f"key={key}, salt1={salt1}, salt={salt2}, secret={secret}")
        pots.append([key, salt1, secret])

    g = combine_mnemonic(pots)
    logging.info(g)

    """
    fucks = combine_mnemonic(requester["email"], shares, salt_one, salt_two)
    decrypted_mnemonic =  encryption_utils.decrypt_mnemonic_privkey(
            requester["encrypted_admin_mnemonic"],
            request.app.config.ADMIN_ZERO_PRIV)


    logging.info(fucks)
    logging.info(decrypted_mnemonic)
    """
    return response.json(
            {
            'error': False,
            'success': True,
            })


@USERS_BP.post('/share_secrets_on_receive_address')
@authorized()
async def share_secrets_on_receive_address(request, requester):
    """
    On a receive_secret address of the requester, there might have been
    several secret_share transactions shared with it  i.e share_secret
    transactions have receive_secret address as their ownership
    """
    required_fields = ["receive_secret_address"]
    validate_fields(required_fields, request.json)
    result = await get_addresses_on_ownership(request.app, request.json["receive_secret_address"])
    return response.json(
            {
            'error': False,
            'success': True,
            "data": result,
            })



@USERS_BP.post('/execute_share_secret')
@authorized()
async def execute_shared_secret(request, requester):
    """
    A user who wanted to share their menmonic secret, split their secret after double
    encryption with scrypt key generated from their menmonic

    Now, every piece was shared on different share_secret transactions created by the user
    the ownership of the execution of these share_secret addresses lies with the
    receive_secret addresses as the ewset key was encrypted with the public key of the
    receive_secret

    So, A user wit whom a part of the secret was shared through their receive_secret
    address, has the authority to execute it..i.e decrypt with the private key of this
    receive_secret, decrypt also the reset key, encrypt the secret with the new reset
    key
    """
    required_fields = ["receive_secret_address", "share_secret_address"]
    validate_fields(required_fields, request.json)

    receive_secret = await resolve_address.ResolveAddress(
                request.json["receive_secret_address"],
                    request.app.config.REST_API_URL)

    ##check if the receive_secret address is indeed a receive_secret
    if receive_secret.type != "RECEIVE_SECRET":
        raise errors.ApiInternalError("This address is not RECEIVE_SECRET contract address")
    else:
        logging.info("Instance is RECEIVE_SECRET")

    share_secret = await resolve_address.ResolveAddress(
                request.json["share_secret_address"],
                    request.app.config.REST_API_URL)

    ##check if the receive_secret address is indeed a receive_secret
    if share_secret.type != "SHARE_SECRET":
        raise errors.ApiInternalError("This address is not SHARE_SECRET contract address")
    else:
        logging.info("Instance is SHARE_SECRET")


    logging.info(share_secret.data)

    if share_secret.data.get("ownership") != request.json["receive_secret_address"]:
        logging.error("Ownership of SHARE_SECRET is not with this RECEIVE_SECRET")


    if not share_secret.data["active"]:
        raise errors.ApiInternalError("This SHARE_SECRET contract is not active")
    ##CHecking if this receive secret is actually belongs to this user
    ##this will checked by getting Public/Private key pair at idx of receiv secret
    ##from the requester mnemonic
    user = await ResolveAccount(requester, request.app)
    requester_mnemonic = user.decrypted_mnemonic

    logging.info(requester_mnemonic)
    index = receive_secret.data["idx"]
    nth_keys = await remote_calls.key_index_keys(request.app, requester_mnemonic,
                                                        [index, 0])

    nth_priv, nth_pub = nth_keys[str(index)]["private_key"], \
                        nth_keys[str(index)]["public_key"]

    if nth_pub != receive_secret.data["public"]:
        logging.error("RECEIVE_SECRET doesnt belong to the requester")
    else:
        logging.info("RECEIVE_SECRET ownership lies with the requester")


    await submit_execute_share_secret(request.app, requester, request.json["receive_secret_address"],
                    share_secret.data, nth_priv, nth_pub)
    return response.json(
            {
            'error': False,
            'success': True,
            })




async def gateway_scrypt_keys(app, password, num_keys, salt):
    async with aiohttp.ClientSession() as session:
        try:
            headers = {"x-api-key": app.config.API_GATEWAY_KEY}
            async with session.post(app.config.API_GATEWAY["SCRYPT_KEYS"],
                     data=json.dumps({"password": password, "num_keys": num_keys, "salt": salt}),
                     headers=headers) as request_response:
                data = await request_response.read()
        except Exception as e:
            logging.error(f"error {e} in {__file__} ")
            raise ApiInternalError("Error with s3 url")
    return json.loads(data)



@USERS_BP.post('/share_mnemonic')
@authorized()
async def share_mnemonic(request, requester):
    """
    When a user taked the responsibility to own their mnemonic,
    if they forget their Mnemonic we cant do anything about it
    """
    ##users has to make sure that these receive_secret_addrs must belong to
    ##different users, Otherwise a same user can join the secrets and brute forse the scrypt
    ##key generated from their email address and decrypt the joined mnemonic
    required_fields = ["receive_secret_addresess", "minimum_required"]

    validate_fields(required_fields, request.json)
    total_shares = request.json["receive_secret_addresess"]

    if request.json["minimum_required"] < 3:
        raise errors.CustomError("To share passwords minimum 3 users are required")

    ##check whether all the receive_secret_addrs are valid
    for addr in request.json["receive_secret_addresess"]:
        try:
            if "RECEIVE_SECRET" != addresser.address_is(addr)[0]:
                raise ApiInternalError("Not a receive_secret address")
        except Exception as e:
            logging.error(e)
            logging.error("Unknown addresses Type")
            raise errors.ApiInternalError("Unknown addresses Type")

    ##TODO, check whether the receive_secret_addresses has any address
    ##which belongs to the user himself/herself.



    ##make all account addresses for all accounts present in the database
    ## Fetch all accounts corresponding to the addresses from the blockchain
    async with aiohttp.ClientSession() as session:
        receive_secrets= await asyncio.gather(*[
            deserialize_state.deserialize_receive_secret(
                            request.app.config.REST_API_URL, address)
                 for address in request.json["receive_secret_addresess"]
        ])

    ##resolving account for the requester to get his decrypted menmonic
    user = await ResolveAccount(requester, request.app)
    logger.debug(user.decrypted_mnemonic)

    ##On the basis of the length of user_accounts, generate random indexes
    ## from the mnemonic and get the PUBlic/private keys corresponding to these
    ##indxs, these, these addresses will be appended to the
    nth_keys_data = await user.generate_shared_secret_addr(
                                len(request.json["receive_secret_addresess"]))

    ##Generate scrypt key from the email and a random salt
    ##encrypt the mnemonic with this AES Key
    ##split the mnemonic, this way even if the user forgets its password, it can be
    ##decrypted using just his email
    logging.info(nth_keys_data)


    ##will be a list of lists wtih each entry, hex encoded [key, salt]
    async with aiohttp.ClientSession() as session:
        result= await asyncio.gather(*[
            gateway_scrypt_keys(request.app, user.org_db["email"], 1, None)
                 for _ in range(0, len(total_shares))
        ])

    ##will be a list of dict with each dict as
    ##{"key": , "salt": , "secret"}, all three being hex encoded
    key_salt_secrets = split_mnemonic(result,
                        user.decrypted_mnemonic, request.json["minimum_required"],
                        len(request.json["receive_secret_addresess"]))

    # user.org_db["email"],

    logger.info(key_salt_secrets)

    #This code block is to test whether the salts generated above give out
    ##the same scrypt keys, which in turn can be used to decrypt the mnemonic shares
    ##and combine them to form the mnemonic
    """
    keys= await asyncio.gather(*[
            gateway_scrypt_keys(request.app, user.org_db["email"], 1, e["salt"])
                 for e in key_salt_secrets
        ])

    g = combine_mnemonic(keys, [e["secret"] for e in key_salt_secrets])
    logger.success(g)

    """
    for (a, receive_secret) in zip(key_salt_secrets, receive_secrets):
        receive_secret.update({"secret": a["secret"], "salt": a["salt"]})



    ##upadting user entry in the users table with the salt which was used in
    ##encrypting mnemonic before it was split into shamir secret shares
    salt_array = [{"salt": e["salt"], "receive_secret_address": e["address"]} \
                                                for e in receive_secrets]
    await update_mnemonic_encryption_salts(request.app, requester["user_id"],
            salt_array)
    #index = list(nth_keys_data.keys())[0]

    ##all the share_secret transaction nonce will be signed by the xeroth
    #private key of the requester so that its authenticatn can be checked
    ##getting zeroth private key of the user
    nth_keys = await remote_calls.key_index_keys(request.app,
                user.decrypted_mnemonic, [0])

    requester_zero_priv =  nth_keys[str(0)]["private_key"]

    ##updating requester data dict with zeroth private key of the requester
    requester.update({"zeroth_private": requester_zero_priv})
    transactions = await share_secret_batch_submit(request.app, requester,
                receive_secrets, nth_keys_data)

    return response.json(
            {
            'error': False,
            'success': True,
            "data": transactions
            })




@USERS_BP.post('/forgot_password')
async def forgot_password(request):
    """
    This api will be used when the user forgot their password
    and they have chosed the second option where they have stored their mnemonic
    with other users on the blockchain.
    """

    required_fields = ["email", "otp_email", "phone_number", "otp_mobile", "new_password"]

    validate_fields(required_fields, request.json)

    required_pattern = re.compile('(?=.{6,})(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&*()])')
    if not required_pattern.match(request.json["new_password"]) or \
                        len(request.json["new_password"]) <= 8:
            raise errors.PasswordStrengthError()



    account_db = await accounts_query.find_user(request.app, request.json["phone_number"],
                        request.json["email"])

    if not account_db:
        raise CustomError("This user doesnt exists, Please register first")

    otp_email = int(request.json["otp_email"])
    otp_mobile = int(request.json["otp_mobile"])

    await verify_otp(request.app, otp_email, request.json["email"],
                        otp_mobile, request.json["phone_number"])

    if account_db["role"] == "USER":
        address = addresser.user_address(account_db["acc_zero_pub"], 0)
        state = await deserialize_state.deserialize_user(
                        request.app.config.REST_API_URL,
                        address)

        logging.info(state)

        await activate_secret_batch_submit(request.app, account_db, request.json["new_password"])
    elif account_db["role"] == "ORGANIZATION":
        address = addresser.organization_address(account_db["acc_zero_pub"], 0)

    elif account_db["role"] == "CHILD":
        ##TODO
        pass
    else:
        raise CustomError("Undefined role for this user")


    logging.info(state)

    return response.json(
               {
                'error': False,
                'success': True,
                'message': "Success",
                })




async def verify_otp(app, otp_email, email,  otp_mobile, phone_number):

    otp_mobile_db = await accounts_query.find_mobile_otp(
                        app, phone_number)

    otp_email_db = await accounts_query.find_email_otp(
                        app, email)

    if not otp_mobile_db:
        raise errors.CustomError("No mobile otp exists")

    if not otp_email_db:
        raise errors.CustomError("No Email otp exists")

    #if not otp_email["otp_verified"]:
    #    raise errors.CustomError("This account has already been verified")


    if otp_mobile != otp_mobile_db["mobile_otp"]:
        logging.info(f"OTP_MOBILE <{otp_mobile}> OTP_MOBILE_DB <{otp_mobile_db}>")
        raise errors.CustomError("OTP received is incorrect for phone_number")
    logging.info("Otp for mobile has been verified")


    if otp_email != otp_email_db["email_otp"]:
        raise errors.CustomError("OTP received is incorrect for email")
    logging.info("otp for email has been verified")


    if otp_mobile_db["validity"] < now_time_stamp():
        raise errors.CustomError("Validity of OTP expired, please generate otp again")
    #await accounts_query.account_verified(app, email, phone_number)

    return





@USERS_BP.post('/get_otps')
async def get_otp(request):
    required_fields = ["email", "phone_number"]
    validate_fields(required_fields, request.json)
    if len(str(request.json["phone_number"])) != 10:
        raise errors.CustomError("Incoreect length of Phone number")

    account_db = await accounts_query.find_user(request.app, request.json["phone_number"],
                        request.json["email"])


    validity = revoke_time_stamp(days=0, hours=2, minutes=0)
    logging.info(account_db)
    await ses_email(request.app, request.json["email"], account_db["user_id"],
                    validity, "Recovery OTP from Remedium", recovery=True)

    await send_message(request.app, account_db["user_id"],
                account_db["first_name"]+" " +account_db["last_name"] ,
                    request.json["phone_number"], validity)

    return response.json(
               {
                'error': False,
                'success': True,
                'message': "Please check your Email and Phone number for OTP",
                })




@USERS_BP.post('/create_receive_secret')
@authorized()
async def receive_secret(request, requester):
    """
    Wheneve a user shares their secret with other users, the user must
    have a receive_secret address, which must be generated from his mnemonic
    at some random index, this index will then be appended to users receive_secret_idxs
    array
    """


    if requester["role"] == "USER":
        requester_address = addresser.user_address(requester["acc_zero_pub"], 0)
    else:
        ##handle case for organization
        pass

    ##resolving account for the requester to get his decrypted menmonic
    user = await ResolveAccount(requester, request.app)
    logging.info(user.decrypted_mnemonic)


    if user.org_state.get("receive_secret_idxs"):
        if len(user.org_state.get("receive_secret_idxs"))  >= \
                                        request.app.config.MAX_RECEIVE_SECRET:
            raise errors.ApiInternalError("Maximum amount of rceive_secret \
                                addresses limit reached")

    data = await submit_receive_secret(request.app, requester["user_id"],
                    user.org_state,
                    requester_address, user.decrypted_mnemonic)

    return response.json(
        {
        'error': False,
        'success': True,
        "data": data
        })



@USERS_BP.post('/get_receive_secrets')
@authorized()
async def receive_secret(request, requester):
    """
    Allt
    """
    f = await ResolveAccount(requester, request.app)

    receive_secret_addrs = await f.receive_secrets()

    if not receive_secret_addrs:
        raise errors.ApiInternalError("Empty receive secrets for this user")


    for element in receive_secret_addrs:
        logging.info(addresser.address_is(element))

    async with aiohttp.ClientSession() as session:
        receive_secret_contracts= await asyncio.gather(*[
            deserialize_state.deserialize_receive_secret(
                    request.app.config.REST_API_URL, address)
                for address in receive_secret_addrs
        ])
    return response.json(
        {
        'error': False,
        'success': True,
        "data": receive_secret_contracts
        })




@USERS_BP.get('/get_account')
@authorized()
async def get_account(request, requester):
    #To get all the account created by the requester

    f = await ResolveAccount(requester, request.app)

    return response.json(
        {
        'error': False,
        'success': True,
        "data": f.org_state,
        })


"""
@ACCOUNTS_BP.get('accounts/get_float_accounts')
@authorized()
async def get_float_accounts(request, requester):
    #To get all the account created by the requester

    float_account_idxs = requester.get("float_account_idxs")
    if not float_account_idxs:
        raise errors.CustomError("No float accounts have been floated corresponding to this account")
    f = await SolveAccount(requester, request.app)
    address_list = await f.float_account_addresses()

    async with aiohttp.ClientSession() as session:
        float_accounts= await asyncio.gather(*[
            deserialize_state.deserialize_float_account(request.app.config.REST_API_URL, address)
                for address in address_list
        ])

    headers, data =format_get_float_accounts(float_accounts)
    return response.json(
        {
        'error': False,
        'success': True,
        'message': "Get Float accounts has been resolved",
        "data": data,
        "headers": headers
        })




@ACCOUNTS_BP.get('accounts/get_children')
@authorized()
async def get_children(request, requester):

    f = await SolveAccount(requester, request.app)
    address_list = await f.children()

    async with aiohttp.ClientSession() as session:
        children= await asyncio.gather(*[
            deserialize_state.deserialize_child(request.app.config.REST_API_URL, address)
                for address in address_list
        ])

    headers, children = format_get_children(children)

    return response.json(
            {
                'error': False,
                'success': True,
                'message': "Child Account has been created",
                'data': children,
                'headers': headers
                             })




@ACCOUNTS_BP.post('accounts/create_child')
@authorized()
async def create_child(request, requester):
    #Lets say NABL claimed their Float account and NOw
    #have Account transaction on the blockchain, This Account trasaction will automatically
    #become the admin for this organization

    #It can create, delete or edit the CHILD accounts associated with it.
    #Now NABL as an organization might have several users, They want to create
    #several other users who would use this platform but on th ebehlaf of NABL

    ##every Organization can create their child and By default every user other then
    #child is an orgnization on this platform
    #TODO if the account has been claimed or not
    required_fields = ["first_name", "last_name",
                                "email", "password", "phone_number"]

    validate_fields(required_fields, request.json)
    if requester["role"] == "CHILD":
        raise Exception("CHILD cannot create anothe child")


    child = await accounts_db.find_on_key(request.app,
                            "email", request.json["email"])

    if child:
        raise errors.AccountError(f"Child account with {request.json['email']} \
        already exists")

    new_child = await new_account(request.app, requester["pancard"],
                        request.json["phone_number"], request.json["email"],
                        "CHILD", requester["gst_number"],
                        requester["tan_number"], requester["org_name"])


    required_pattern = re.compile('(?=.{6,})(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&*()])')
    if not required_pattern.match(request.json["password"]) or \
                        len(request.json["password"]) <= 8:
            raise errors.PasswordStrengthError()

    mnemonic, child = await set_password(request.app, new_child,
                        request.json["password"],
                        requester["pancard"])


    child.update({"first_name": request.json["first_name"],
                    "last_name": request.json["last_name"]})

    user = await submit_child_account(request.app, requester, child)
    return response.json(
            {
                'error': False,
                'success': True,
                'message': "Child Account has been created",
                'data': {"user": user}
            })




@ACCOUNTS_BP.post('accounts/claim_account')
async def claim_account(request):
    #When a float account of the user exists and now he/she wants to claim it

    #Args:
    #    pancard(string): pancard of the user
    #    email(string): Email of the user
    #    phone_number(string): Phone number of the user
    #    password(string): Password desired by the user

    required_fields = ["org_name", "email", "pancard", "otp_email", "otp_mobile",
                "gst_number", "tan_number", "phone_number", "password"]
    validate_fields(required_fields, request.json)
    await verify_otp(request.app, request.json["otp_email"], request.json["email"],
                    request.json["otp_mobile"], request.json["phone_number"])



    ##TODO: check if email, phone and pancard is valid or not
    ##check validity of the password
    required_pattern = re.compile('(?=.{6,})(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&*()])')
    if not required_pattern.match(request.json["password"]) or \
                        len(request.json["password"]) <= 8:
            raise errors.PasswordStrengthError()

    ##Finding the user in pending table, if he doesnt exists error
    pending_user = await accounts_db.find_pending_account(request.app,
                            request.json["pancard"],
                            request.json["email"])

    if not pending_user:
        raise errors.PendingAccountError()

    #if user exists but his/her account has already been claimed
    if pending_user["claimed"]:
        raise errors.ClaimAccountError()


    if pending_user["org_name"] != request.json["org_name"]:
        raise Exception("Organization name doesnt match")


    if pending_user["phone_number"] != request.json["phone_number"]:
        raise Exception("Organization phone_number doesnt match")


    ##decrypt the user password which was encrypted at by the ADMIN public at the
    ## time of float_account transaction, also encrypt the user
    ##mnemonic and store it the database encrypted_mnemonic
    mnemonic, updated_user = await set_password(request.app, pending_user, request.json["password"],
                        request.json["pancard"])

    logging.info(f"This is the updated user with encrypted_mnemonic {updated_user}")


    gst_number = hashlib.sha224(request.json["gst_number"].encode()).hexdigest()
    if pending_user["gst_number"]:
        if gst_number != pending_user["gst_number"]:
            raise Exception("Wrong gst_number provided, make sure to provide \
                the gst_number as entered while float_account creation")


    tan_number = hashlib.sha224(request.json["tan_number"].encode()).hexdigest()
    if pending_user["tan_number"]:
        if tan_number != pending_user["tan_number"]:
            raise Exception("Wrong tan_number provided, make sure to provide \
                the tan_number as entered while float_account creation")


    updated_user.update({"gst_number": gst_number,
                "tan_number": tan_number,
                "mnemonic": mnemonic}) #thismnemonic must be removed before
                ## stroing into the database
    ##This is just for Test whether we can decrypt the encrypted_mnemonic or not,
    ##remove it in production
    logging.info(updated_user)

    user_id = pending_user['user_id']


    user = await submit_organization_account(request.app, updated_user)
    mnemonic = await user_mnemonic_frm_password(request.app, updated_user,
                                                    request.json["password"])

    logging.info(mnemonic)
    return response.json(
        {
            'error': False,
            'success': True,
            'message': "Account has been created",
            "data": {"user_mnemonic": mnemonic}
        })




@ACCOUNTS_BP.post('accounts/deactivate_account')
@authorized()
async def deactivate_account(request, requester):
    pass
"""
