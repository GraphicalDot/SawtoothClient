
##deals with the registration of the users

from sanic.request import RequestParameters
from .authorization import authorized
from routes.route_utils import validate_fields
from routes.route_utils import new_account
from routes.route_utils import set_password
from routes.route_utils import user_mnemonic_frm_password, sendEmail, sendMessage
import hashlib
from db import accounts_query

from sanic import response
from errors import errors
import db.accounts_query as accounts_db
import re
#from ledger.accounts.float_account.submit_float_account import submit_float_account
from ledger.accounts.organization_account.submit_organization_account import submit_organization_account
#from ledger.accounts.child_account.submit_child_account import submit_child_account
from remotecalls import remote_calls
from addressing import addresser
from encryption import utils as encryption_utils
from addressing import addresser
from encryption import asymmetric
from encryption import symmetric
from encryption import signatures
import aiohttp
import asyncio

from ledger import deserialize_state

import coloredlogs, logging
coloredlogs.install()


from ._format_api_result import format_get_organization_account,\
                                format_get_children,\
                                format_get_float_accounts



from sanic import Blueprint
USERS_BP = Blueprint('users', url_prefix='/users')

def asyncinit(cls):
    __new__ = cls.__new__

    async def init(obj, *arg, **kwarg):
        await obj.__init__(*arg, **kwarg)
        return obj

    def new(cls, *arg, **kwarg):
        obj = __new__(cls, *arg, **kwarg)
        coro = init(obj, *arg, **kwarg)
        #coro.__init__ = lambda *_1, **_2: None
        return coro

    cls.__new__ = new
    return cls







@USERS_BP.get('/address')
async def get_address(request):
    """
    """
    address = request.args.get("address")

    if not address:
        raise errors.CustomError("address is required")

    instance = await SolveAddress(address, request.app.config.REST_API_URL)
    return response.json(
            {
            'error': False,
            'success': True,
            'message': f"{instance.type} type found",
            "data": instance.data,
            })







@USERS_BP.get('/registration')
async def register_user(request):
    """
    """
    address = request.args.get("address")

    if not address:
        raise errors.CustomError("address is required")

    instance = await SolveAddress(address, request.app.config.REST_API_URL)
    return response.json(
            {
            'error': False,
            'success': True,
            'message': f"{instance.type} type found",
            "data": instance.data,
            })




@USERS_BP.get('/registration_no_mnemonic')
async def register_user_no_mnemonic(request):
    """
    When a user taked the responsibility to own their mnemonic,
    if they forget their Mnemonic we cant do anything about it
    """
    address = request.args.get("address")

    if not address:
        raise errors.CustomError("address is required")

    instance = await SolveAddress(address, request.app.config.REST_API_URL)
    return response.json(
            {
            'error': False,
            'success': True,
            'message': f"{instance.type} type found",
            "data": instance.data,
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



@ACCOUNTS_BP.post('accounts/get_otp')
async def get_otp(request):
    required_fields = ["email", "phone_number"]
    validate_fields(required_fields, request.json)
    if len(str(request.json["phone_number"])) != 10:
        raise errors.CustomError("Incoreect length of Phone number")

    pending_user = await accounts_db.find_pending_account_email_phone(request.app,
                            request.json["phone_number"],
                            request.json["email"])

    if not pending_user:
        raise errors.PendingAccountError()

    #if user exists but his/her account has already been claimed
    if pending_user["claimed"]:
        raise errors.ClaimAccountError()

    validity = upload_utils.revoke_time_stamp(days=0, hours=0, minutes=10)
    await sendEmail(request.app, pending_user["user_id"],
                    request.json["email"], validity)
    await sendMessage(request.app, pending_user["user_id"],
                    request.json["phone_number"], validity)
    return response.json(
               {
                'error': False,
                'success': True,
                'message': "Please check your Email and Phone number for OTP",
                })


async def verify_otp(app, otp_email, email,  otp_mobile, phone_number):

    otp_mobile = await accounts_query.find_mobile_otp(
                        app, phone_number)

    otp_email = await accounts_query.find_email_otp(
                        app, email)

    if not otp_mobile:
        raise errors.CustomError("No mobile otp exists")


    if not otp_email:
        raise errors.CustomError("No Email otp exists")

    if not otp_email["otp_verified"]:
        raise errors.CustomError("This account has already been verified")



    if otp_mobile != otp_mobile:
        raise CustomError("OTP received is incorrect for phone_number")


    if otp_email != otp_email:
        raise CustomError("OTP received is incorrect for email")

    right_now = upload_utils.revoke_time_stamp(days=0, hours=0, minutes=10)

    if otp_mobile["validity"] < right_now:
        raise errors.CustomError("Validity of OTP expired, please generate otp again")


    await accounts_query.account_verified(app, email, phone_number)

    return

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
