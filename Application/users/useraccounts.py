
##deals with the registration of the users

from sanic import Blueprint
from sanic.request import RequestParameters
from .authorization import authorized
from .utils import validate_fields
from .utils import new_account
from .utils import set_password
from .utils import user_mnemonic_frm_password, sendEmail, sendMessage
import hashlib
from db import accounts_query

from sanic import response
from errors import errors
import upload.utils as upload_utils
import db.accounts_query as accounts_db
import re
from ledger.accounts.float_account.submit_float_account import submit_float_account
from ledger.accounts.create_organization_account.submit_create_organization_account import submit_organization_account
from ledger.accounts.child_account.submit_child_account import submit_child_account
from remotecalls import remote_calls
from addressing import addresser
from encryption import utils as encryption_utils
from addressing import addresser
from encryption import asymmetric
from encryption import symmetric
from encryption import signatures
import aiohttp
import asyncio

import ledger.utils as ledger_utils
from ledger import deserialize_state

import coloredlogs, logging
coloredlogs.install()



from ._format_api_result import format_get_organization_account,\
                                format_get_children,\
                                format_get_float_accounts


USER_ACCOUNTS_BP = Blueprint('useraccounts')
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

class aobject(object):
    """Inheriting this class allows you to define an async __init__.

    So you can create objects by doing something like `await MyClass(params)`
    """
    async def __new__(cls, *a, **kw):
        instance = super().__new__(cls)
        await instance.__init__(*a, **kw)
        return instance

    async def __init__(self):
        pass







class SolveAccount(aobject):

    async def __init__(self, requester, app):
        """
        decrypted_nemonic will be mnemonic for either parent org of child
        or org itself, child mnemonic has no use as of now

        self.org_address
                address of the orgnization itself, if requester is
                organization

                address of the parent_organization, is requester is
                child

                address of the float_account, if requester is float_account

        """
        self.app = app
        self.requester = requester

        if requester["role"] == "CHILD":
            ##The parent org zeroth public key will be used
            self.org_address, self.org_state, self.org_db = \
                        await self.org_details(requester["parent_zero_pub"])
            self.child_address, self.child_state, self.child_db = \
                                await self.child_details(requester["public"])
            await self.check_child()
            self.role = self.org_state["role"]
            self.child_zero_pub = requester["public"]
            self.child_user_id = self.child_db["user_id"]
            self.zero_pub = self.org_state["public"] ##this will be added as a
            ##reference to asset to reflect which org account issues this certificate
        else:
            ##this means the requester is orgnization itself, so its child_user_id
            ## and child_zero_pub is None,
            self.org_address, self.org_state, self.org_db= \
                            await self.org_details(requester["acc_zero_pub"])
            self.child_address, self.child_state = None, None
            self.role = requester["role"]
            self.child_zero_pub = None
            self.child_user_id = None

            if not self.org_state:
                ##this means that the requester is float_Account, only another
                ## orgnization on behalf of this float_accout can act,
                ## because float_account himself cant even login
                logging.info("This is a Float account, from SolveAccount")
                ##this means that requester is a float_account, the requester
                ##float account adress can be generated with
                ##TODO delete parent_pub on entriesin float_Accounts and replace it with public
                self.org_address, self.org_state, self.org_db= await \
                        self.pending_details(
                                        requester["parent_pub"],
                                        requester["parent_idx"])
                self.zero_pub = None
                self.child_user_id = None
            else:
                self.zero_pub = self.org_state["public"] ##this will be added as a


        self.decrypted_mnemonic = await self.decrypt_mnemonic()
        ##this will populate two calss variables, org_address and org_state





    async def pending_details(self, public, index):
        float_org_address = addresser.float_account_address(
                            public, index)

        float_org_state = await deserialize_state.deserialize_float_account(
                            self.app.config.REST_API_URL, float_org_address)

        float_org_db = await accounts_query.find_on_key_pending(self.app,
                                "parent_pub", public)

        return float_org_address, float_org_state, float_org_db



    async def org_details(self, public):
        org_address = addresser.create_organization_account_address(
                            public, 0)

        org_state = await deserialize_state.deserialize_org_account(
                            self.app.config.REST_API_URL, org_address)

        if org_state:##it means the accountis still float
            org_db = await accounts_query.find_on_key(self.app, "user_id",
                                        org_state["user_id"])
        else:
            org_db = None
        return org_address, org_state, org_db


    async def child_details(self, public):
        child_address = addresser.child_account_address(
                            public, 0)

        child_state = await deserialize_state.deserialize_child(
                            self.app.config.REST_API_URL, child_address)
        child_db = await accounts_query.find_on_key(self.app, "user_id",
            child_state["user_id"])

        return child_address, child_state, child_db


    ##check whether, if child is valid child or not
    async def check_child(self):
        if self.requester["parent_idx"] not in self.org_state["child_account_idxs"]:
            raise errors.CustomError("Child parent_idx not in parent org child_account_idxs")


        if self.requester["org_name"] != self.org_state["org_name"]:
            raise errors.CustomError("Child org_name is different from  parent")

        return


    async def decrypt_mnemonic(self):
        if self.role == "ADMIN":
            decrypted_mnemonic = self.app.config.ADMIN_MNEMONIC

        else:
            ##if we are getting float accounts for admin directly
            decrypted_mnemonic = await ledger_utils.decrypted_user_mnemonic(
                self.app,
                self.org_db["encrypted_admin_mnemonic"],
                self.role)
        return decrypted_mnemonic





    async def indexes_n_pub_priv_pairs(self, array_name):
        if self.requester["role"] == "CHILD":
            idxs = self.child_state.get(array_name)
            if not idxs:
                raise errors.CustomError(f"No  {array_name} exists for this account")
        else:
            idxs = self.org_state.get(array_name)

        if idxs:
            nth_keys = await remote_calls.key_index_keys(self.app,
                            self.decrypted_mnemonic, idxs)
            return idxs, nth_keys
        return [], False

    async def float_account_addresses(self):
        float_account_idxs, nth_keys = await self.indexes_n_pub_priv_pairs("float_account_idxs")
        address_list = []
        address_list = []
        nth_keys = await remote_calls.key_index_keys(self.app,
                            self.decrypted_mnemonic, float_account_idxs)

        for key_index in float_account_idxs:
            public_key = nth_keys[str(key_index)]["public_key"]
            child_address = addresser.float_account_address(
                    account_id=public_key,
                    index=key_index
                    )
            address_list.append(child_address)
        return address_list

    async def assets(self):
        logging.info("Finding all the assets from the SOlve account")
        create_asset_idxs, nth_keys = await self.indexes_n_pub_priv_pairs("create_asset_idxs")
        address_list = []
        if create_asset_idxs:
            for key_index in create_asset_idxs:
                public_key = nth_keys[str(key_index)]["public_key"]
                child_address = addresser.create_asset_address(
                        asset_id=public_key,
                        index=key_index
                        )
                address_list.append(child_address)

        logging.info(f"Asset address list <<{address_list}>>")
        return address_list

    async def receive_assets(self):
        receive_asset_idxs, nth_keys = await self.indexes_n_pub_priv_pairs("receive_asset_idxs")
        address_list = []
        for key_index in receive_asset_idxs:
            public_key = nth_keys[str(key_index)]["public_key"]
            receive_asset_address = addresser.receive_asset_address(
                    asset_id=public_key,
                    index=key_index
                    )
            address_list.append(receive_asset_address)
        logging.info(f"Asset address list <<{address_list}>>")
        return address_list

    async def share_assets(self):
        share_asset_idxs, nth_keys = await self.indexes_n_pub_priv_pairs("share_asset_idxs")
        address_list = []
        for key_index in share_asset_idxs:
            public_key = nth_keys[str(key_index)]["public_key"]
            share_asset_address = addresser.share_asset_address(
                    asset_id=public_key,
                    index=key_index
                    )
            address_list.append(share_asset_address)
        logging.info(f"Asset address list <<{address_list}>>")
        return address_list

    async def children(self):
        child_account_idxs, nth_keys = await self.indexes_n_pub_priv_pairs("child_account_idxs")
        address_list = []
        for key_index in child_account_idxs:
            public_key = nth_keys[str(key_index)]["public_key"]
            child_address = addresser.child_account_address(
                    account_id=public_key,
                    index=0
                    )
            address_list.append(child_address)
        logging.info(f"child account addresses <<{address_list}>>")
        return address_list


class SolveAddress(aobject):
    async def __init__(self, address, rest_api_url):
        self.address = address

        self.address_type, self.account_index = addresser.address_is(address)
        logging.info(f"{address}, {self.address_type}, {self.account_index}")
        print (f"{address}, {self.address_type}, {self.account_index}")
        self.rest_api_url = rest_api_url

        self.data = None
        if self.address_type=="FLOAT_ACCOUNT":
            logging.info("Address is FLOAT_ACCOUNT")
            self.type = "FLOAT_ACCOUNT"
            self.data = await deserialize_state.deserialize_float_account(
                        self.rest_api_url, self.address)



        elif self.address_type=="ORGANIZATION_ACCOUNT":
            logging.info("Address is ORGANIZATION_ACCOUNT")
            self.type = "ORGANIZATION_ACCOUNT"
            self.data = await deserialize_state.deserialize_org_account(
                        self.rest_api_url, self.address)


        elif self.address_type=="CHILD_ACCOUNT":
            logging.info("Address is CHILD_ACCOUNT")
            self.type = "CHILD_ACCOUNT"
            self.data = await deserialize_state.deserialize_child(
                        self.rest_api_url, self.address)


        elif self.address_type=="USER_ACCOUNT":
            logging.info("Address is USER_ACCOUNT")
            self.type = "USER_ACCOUNT"
            self.data = await deserialize_state.deserialize_user(
                        self.rest_api_url, self.address)


        elif self.address_type == "CREATE_ASSET":
            logging.info("Address is CREATE_ASSET")
            self.type = "CREATE_ASSET"
            self.data = await deserialize_state.deserialize_asset(
                        self.rest_api_url, self.address)

        elif self.address_type == 'SHARE_ASSET':
            logging.info("Address is SHARE_ASSET")

            self.data = await deserialize_state.deserialize_share_asset(
            self.rest_api_url, self.address)

        elif self.address_type == "RECEIVE_ASSET":
            logging.info("Address is RECEIVE_ASSET")
            self.type = "RECEIVE_ASSET"
            self.data = await deserialize_state.deserialize_receive_asset(
                        self.rest_api_url, self.address)
        else:
            logging.info("Address is Unknown")




@USER_ACCOUNTS_BP.get('accounts/address')
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



@USER_ACCOUNTS_BP.get('accounts/get_organization_account')
@authorized()
async def get_organization_account(request, requester):
    """
    To get all the account created by the requester
    """
    if requester["role"] == "CHILD":

        org_address = addresser.child_account_address(
                    requester["public"], 0)

        org_account = await deserialize_state.deserialize_child(
                    request.app.config.REST_API_URL, org_address)

    else:

        org_address = addresser.create_organization_account_address(
            requester["acc_zero_pub"], 0)

        org_account = await deserialize_state.deserialize_org_account(
            request.app.config.REST_API_URL, org_address)


    headers, data = format_get_organization_account(org_account)
    if org_account:

        return response.json(
            {
            'error': False,
            'success': True,
            'message': "Orgnization account found",
            "data": data,
            "headers": headers
            })
    else:
        raise CustomError("No orgnization account can be found for this user")




@USER_ACCOUNTS_BP.get('accounts/get_float_accounts')
@authorized()
async def get_float_accounts(request, requester):
    """
    To get all the account created by the requester
    """

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




@USER_ACCOUNTS_BP.get('accounts/get_children')
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




@USER_ACCOUNTS_BP.post('accounts/create_child')
@authorized()
async def create_child(request, requester):
    """
    Lets say NABL claimed their Float account and NOw
    have Account transaction on the blockchain, This Account trasaction will automatically
    become the admin for this organization

    It can create, delete or edit the CHILD accounts associated with it.
    Now NABL as an organization might have several users, They want to create
    several other users who would use this platform but on th ebehlaf of NABL

    ##every Organization can create their child and By default every user other then
    child is an orgnization on this platform
    #TODO if the account has been claimed or not
    """
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



@USER_ACCOUNTS_BP.post('accounts/create_organization_account')
@authorized()
async def create_organization_account(request, requester):
    """
    This creates a float_account transaction which user has to claim later
    to perform any action on the blockchain
    Create a organization float account on the the blockchain and store details on the
    database, Requester role will be checked whether it is allowed to create
    an organizaion of the desired role or not

    Child account will not have a float account as we already have a
    gurantee from the orgnisation that it is a valid account,

    If its not, Its the responsibility of the orgnization

    role could be anything like MASTER

    gst_number and tan_number are optional at this stage,
    later when claiming the account pancard of the user must be matched
     with the details of either gst or tan
    """
    required_fields = ["org_name", "email", "pancard",
             "role", "phone_number"]


    validate_fields(required_fields, request.json)
    if requester["role"] == "CHILD":
        role_to_be_checked = requester["parent_role"]
    else:
        role_to_be_checked = requester["role"]

    logging.info(f"This is the role to be checked {role_to_be_checked}")

    if role_to_be_checked not in request.app.config.ALLOWED_ROLES:
        raise Exception(f"Unknown role, '{request.json['user_role']}' ROLE is not defined")

    if request.json["role"] not in request.app.config.ROLES[role_to_be_checked]:
        raise errors.AccountCreationError(
                message=f"The user with user_id {requester['user_id']} is not\
                allowed to create ROLE={request.json['role']}")

    pending_org = await accounts_db.find_pending_account(request.app,
                            request.json["pancard"], request.json["email"])

    if pending_org:
        raise errors.PendingAccountError("Organization accounts already exists")


    ##TODO: SOmehow check whether the same orgnization name has same pancard and email
    ##from some third party government API
    org = await accounts_db.find_account(request.app,
                            request.json["org_name"],
                            request.json["pancard"], request.json["email"])

    if org:
        raise errors.AccountError("Organization account already exists")


    ##Tis implies that the user who wanted to create user_role doesnt
    ##have the permission to do so.


    new_user = await new_account(request.app, request.json["pancard"],
                    request.json["phone_number"], request.json["email"],
                    request.json["role"], request.get("gst_number"),
                    request.get("tan_number"), request.json["org_name"])

    logging.info(f"New user data is {new_user}")

    new_user = await submit_float_account(request.app, requester, new_user)

    #A new asset will be created after generating a random index keys from the
    ##new_user, The transaction will be signed by this random index public key,
    ##after the successful submission the user data must be submitted
    #check if the user has role "ADMIN stored in the database"

    ##if organization_name exists in the DB, reject
    ##implies that organization_name is already registered on the blockchain

    ##now submit a float transaction with the data, which will be claimed later
    ##by the user after verification of their email id and adhaar

    return response.json(
        {
            'error': False,
            'success': True,
            'message': "Float Account has been created",
            'data': {"user": new_user}
        })


@USER_ACCOUNTS_BP.post('accounts/get_otp')
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

@USER_ACCOUNTS_BP.post('accounts/claim_account')
async def claim_account(request):
    """``
    When a float account of the user exists and now he/she wants to claim it

    Args:
        pancard(string): pancard of the user
        email(string): Email of the user
        phone_number(string): Phone number of the user
        password(string): Password desired by the user
    """

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




@USER_ACCOUNTS_BP.post('accounts/deactivate_account')
@authorized()
async def deactivate_account(request, requester):
    """
    """
    pass
