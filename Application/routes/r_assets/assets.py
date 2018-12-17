
import asyncio
from sanic import Blueprint
from db.accounts_query import fetch_info_by_email
from db import accounts_query
from db import assets_query
from errors import errors
import hashlib
from sanic import response
from routes.r_accounts import authorization
from encryption import key_derivations
#from accounts_api import utils as user_utils
#from accounts_api import userapis
from remotecalls import remote_calls
import time
import binascii
import json
import coloredlogs, logging
coloredlogs.install()
import base64
from addressing import addresser
import aiohttp
import asyncio
import db.receive_assets_query as receive_assets_db

#from  ledger.assets.create_asset.submit_create_asset import submit_create_asset
#from  ledger.assets.create_asset.submit_create_asset import submit_empty_asset
#from ledger.accounts.float_account.submit_float_account import submit_float_account
#from ledger.assets.transfer_asset.submit_transfer_asset import  submit_transfer_asset
#from ledger.assets.receive_asset.submit_receive_asset import  submit_receive_asset
#from ledger.assets.utils import  decrypt_keys_from_index



#from ledger.assets.share_asset.submit_share_asset import  submit_share_asset

from routes.r_accounts.authorization import authorized
from ._format_api_result import format_get_assets
CREATE_ASSETS_BP = Blueprint('assets', url_prefix="/")





@CREATE_ASSETS_BP.get('assets')
@authorized()
async def get_assets(request, requester):
    """
    To get all the assets created by the requester
    """


    f = await useraccounts.SolveAccount(requester, request.app)
    address_list = await f.assets()

    logging.info(address_list)
    if address_list:
        async with aiohttp.ClientSession() as session:
            assets= await asyncio.gather(*[
                useraccounts.SolveAddress(address, request.app.config.REST_API_URL)
                    for address in address_list
            ])
        assets=[f.data for f in assets]

    else:
        assets = []

    headers, data = format_get_assets(assets)

    return response.json(
        {
        'error': False,
        'success': True,
        "data": data ,
        "headers": headers
        })



@CREATE_ASSETS_BP.post('create_asset')
@authorization.authorized()
async def create_asset(request, requester):
    required_fields = ["file_name", "base64_file_bytes", "file_hash",
                    "expired_on", "scope"]

    ##TODO check if the expired on datetime must be greater then 45 days from
    ##TODAY
    user_utils.validate_fields(required_fields, request.json)

    file_bytes = upload_utils.base64decoding(request.json["base64_file_bytes"])

    file_data = {"file_name": request.json["file_name"],
                "data": request.json["base64_file_bytes"],
                "file_hash": request.json["file_hash"],
                "scope": request.json["scope"],
                "expired_on": request.json["expired_on"]}

    if not isinstance(request.json["base64_file_bytes"], str):
            raise Exception("file_bytes must be string")



    upload_utils.check_hash(file_bytes, request.json["file_hash"])

    ##check if same file hash exists in the system, meaning duplicate certificates
    is_file_hash = await assets_query.check_filehash_assets(
                                    request.json["file_hash"],
                                    request.app.config.DB)
    if not is_file_hash:
        raise errors.ApiBadRequest("The same file hash has been uploaded by other user")

    ##this claimed=True because only thenuser will be able to login because its
    ##entry is present in users table, i.e it has orgnization account on blockchain
    usr_nth_priv, usr_nth_pub, usr_key_index, usr_address = \
                await submit_create_asset(request.app, requester, file_data)

    return response.json(
        {
        'error': False,
        'success': True,
        'data': {"private_key": usr_nth_priv,
                "public_key": usr_nth_pub,
                "key_index": usr_key_index,
                "address": usr_address,
                }
                })



"""

@UPLOAD_BP.get('assets/share_assets')
@authorized()
async def get_share_assets(request, requester):


    f = await useraccounts.SolveAccount(requester, request.app)
    address_list = await f.share_assets()

    logging.info(address_list)
    if address_list:
        async with aiohttp.ClientSession() as session:
            assets= await asyncio.gather(*[
                useraccounts.SolveAddress(address, request.app.config.REST_API_URL)
                    for address in address_list
            ])
        assets=[f.data for f in assets]

    else:
        assets = []


    return response.json(
        {
        'error': False,
        'success': True,
        'message': "Get Float accounts has been resolved",
        "data": assets ,
        })



@UPLOAD_BP.get('assets/decrypt_keys')
@authorized()
async def decrypt_keys(request, requester):
    address = request.args.get("address")

    if not address:
        raise errors.CustomError("address is required")

    logging.info(f"This is the address for decrypting keys {address}")
    instance = await useraccounts.SolveAddress(address, request.app.config.REST_API_URL)
    if instance.address_type not in ["CREATE_ASSET", "RECEIVE_ASSET", "SHARE_ASSET"]:
        raise errors.CustomError("This address doesnt have any keys to decrypt {instance.address_type}")



    key, url, file_data = await decrypt_keys_from_index(request.app, requester, instance.data)

    file_data = base64.b64decode(file_data).decode()
    key = binascii.hexlify(key).decode()
    url = url.decode()
    return response.json(
        {
        'error': False,
        'success': True,
        "data": {"key": key, "url": url, "file_data": file_data}
        })


@UPLOAD_BP.get('assets/receive_assets')
@authorized()
async def get_receive_assets(request, requester):


    f = await useraccounts.SolveAccount(requester, request.app)
    address_list = await f.receive_assets()

    async with aiohttp.ClientSession() as session:
        assets= await asyncio.gather(*[
            useraccounts.SolveAddress(address, request.app.config.REST_API_URL)
                for address in address_list
        ])


    ##fetching bare unique_code present in the database and not on the blockchain
    async with aiohttp.ClientSession() as session:
        result= await asyncio.gather(*[
            receive_assets_db.receive_asset_unique_code(request.app, f.data)
                for f in assets
        ])


    return response.json(
        {
        'error': False,
        'success': True,
        'message': "Get receive assets  has been resolved",
        "data": result,
        })



@UPLOAD_BP.post('assets/create_receive_asset')
@authorization.authorized()
async def create_receive_asset(request, requester):

    required_fields = ["_id_", "name",
                "description", "at_which_asset_expires"]

    ##TODO check if the expired on datetime must be greater then 45 days from
    ##TODAY
    user_utils.validate_fields(required_fields, request.json)

    nth_pub, key_index, receive_asset_address = await submit_receive_asset(request.app,
                        requester,
                        request.json["_id_"],
                        request.json["name"],
                        request.json["description"],
                        request.json["at_which_asset_expires"])


    if nth_pub:
            return response.json(
            {
                'error': False,
                'success': True,
                "message": f"Receive asset created succesfully for {requester['user_id']}",
                "data": {
                    "public": nth_pub,
                    "index": key_index,
                    "address": receive_asset_address,
                }
            })
    else:
        logging.error("Error in transffering assets")

@UPLOAD_BP.post('assets/share_asset')
@authorization.authorized()
async def share_asset(request, requester):
    #If the requester only have float_account and havent claimed his account
    #The request will fail in authorization only or it will fail while login only

    #Unique code is required to share asset with receive asset to debar users
    #to unecessarily heck receiver_asset address

    #The type of unique code is int, which then converted to string and sha224
    #and matched with unique_code_hash present on the receivers_asset address
    required_fields = ["asset_address", "receive_asset_address", "unique_code",
                "revoked_on", "comments"]
    ##TODO check if the expired on datetime must be greater then 45 days from
    ##TODAY
    user_utils.validate_fields(required_fields, request.json)
    if type(request.json["unique_code"]) != int:
        raise CustomError("Unique must be int type")

    if upload_utils.revoke_time_stamp(days=0, hours=0, minutes=30) > request.json["revoked_on"]:
        raise errors.InvalidValidityPeriod()

    result = await submit_share_asset(request.app,
                        requester,
                        request.json["asset_address"],
                        request.json["receive_asset_address"],
                        request.json["unique_code"],
                        request.json["revoked_on"],
                        request.json["comments"])

    if result:
            return response.json(
            {
                'error': False,
                'success': True,
                'message': f"Asset have been transfferred",
                 "data": {
                    "share_asset_address": result
                 }
            })
    else:
        logging.error("Error in transffering assets")


@UPLOAD_BP.post('assets/cert_transfer')
@authorization.authorized()
async def cert_transfer(request, requester):
    required_fields = ["issuer_address", "receiver_address", "expired_on"]

    ##TODO check if the expired on datetime must be greater then 45 days from
    ##TODAY
    user_utils.validate_fields(required_fields, request.json)

    result = await submit_transfer_asset(request.app,
                        requester,
                        request.json["issuer_address"],
                        request.json["receiver_address"],
                        expired_on=request.json["expired_on"])

    if result:
            return response.json(
            {
                'error': False,
                'success': True,
                'message': "Asset have been transfferred from \
                {request.json['issuer_address']} to {request.json['receiver_address']}"
            })
    else:
        logging.error("Error in transffering assets")







@UPLOAD_BP.post('assets/upload')
@authorization.authorized()
async def upload(request, requester):
    #Only a certificate can be uploaded for a float_account, orgnization_account
    #or child_account.

    #The process is this:
    #        Check if the address if float_account, orgnization_account or
    #        child_account
    ##pancard is not mandatory
    required_fields = ["file_name", "base64_file_bytes", "file_hash",
                "scope", "expired_on", "address"]
    user_utils.validate_fields(required_fields, request.json)

    instance = await useraccounts.SolveAddress(
                    request.json["address"], request.app.config.REST_API_URL)

    if instance.type not in ["CHILD_ACCOUNT", "ORGANIZATION_ACCOUNT",
                    "USER_ACCOUNT", "FLOAT_ACCOUNT"]:
            raise errors.CustomError("This address is not acceptable")


    if instance.type == "FLOAT_ACCOUNT":
        if instance.data.get("claimed"):
            raise errors.CustomError("FLoat account has already been claimed, Please \
            send orgnization account of this address for issuing a certificate")
        else:
            claimed = False
            logging.info(instance.data)

            receiver_db = await accounts_query.find_on_key_pending(request.app,
                                        "email", instance.data["email"])
    else:
        claimed = True
        receiver_db = await accounts_query.find_on_key(request.app,
                                "email", instance.data["email"])


    if requester["role"] == "CHILD":
         if instance.data["role"] not in request.app.config.ROLES[requester["parent_role"]]:
            raise errors.AccountCreationError("dwfcascfa")
    else:
         if instance.data["role"] not in request.app.config.ROLES[requester["role"]]:
            raise errors.AccountCreationError("dfaffd")


    ##NOw check if the user has provided time for which the document will be
    ## shared  or the document will be valid for less than 30 days
    if upload_utils.revoke_time_stamp(days=1) > request.json["expired_on"]:
        raise errors.InvalidValidityPeriod()

    file_bytes = upload_utils.base64decoding(request.json["base64_file_bytes"])

    file_data = {"file_name": request.json["file_name"],
                "data": request.json["base64_file_bytes"],
                "file_hash": request.json["file_hash"],
                "scope": request.json["scope"],
                "expired_on": request.json["expired_on"]}

    if not isinstance(request.json["base64_file_bytes"], str):
            raise Exception("file_bytes must be string")



    upload_utils.check_hash(file_bytes, request.json["file_hash"])

    ##check if same file hash exists in the system, meaning duplicate certificates
    is_file_hash = await assets_query.check_filehash_assets(
                                    request.json["file_hash"],
                                    request.app.config.DB)
    if not is_file_hash:
        raise errors.ApiBadRequest("The same file hash has been uploaded by other user")
    ##check if this combination of pancard and phone_number exists in the database
    ##in the users_table
    logging.info(f"receiver_db {receiver_db}")
    receiver_priv, receiver_pub, receiver_index, receiver_address = \
                    await submit_empty_asset(request.app, receiver_db, claimed)

    logging.info("NOw creating a non empty asset")
    issuer_priv, issuer_pub, issuer_index, issuer_address = await \
                 submit_create_asset(request.app, requester, file_data)


    #        make_transfer_asset(request, requester, user, file_data,
    #            claimed=claimed, expired_on=request.json["expired_on"])
    transfer_asset_result =  await submit_transfer_asset(request.app,
                            requester,
                            issuer_address,
                            receiver_address,
                            expired_on=request.json["expired_on"])

    return response.json(
            {
                'error': False,
                'success': True,
                'data': {
                    "issuer_address": issuer_address,
                    "receiver_address": receiver_address,
                    "message": "Asset have been created and transferred from"
                        }
            })







async def transfer_asset(request, parent, user, file_data, claimed, expired_on):
    logging.info("Creating an empty asset for the user")
    usr_nth_priv, usr_nth_pub, usr_key_index = \
                await submit_create_asset(request.app, user, None,
                    claimed=claimed)


    receiver_address= addresser.create_asset_address(
                    asset_id=usr_nth_pub,
                    index=usr_key_index)


    ##since parent can only login if the account has been claimed
    parent_nth_priv, parent_nth_pub, parent_key_index = \
            await submit_create_asset(request.app, parent, file_data,
                claimed=True)



    issuer_address= addresser.create_asset_address(
                    asset_id=parent_nth_pub,
                    index=parent_key_index)


    logging.error(f"user_nth_pub {usr_nth_pub}, usr_key_index {usr_key_index} receiver_address {receiver_address}")
    logging.error(f"parent_nth_pub {parent_nth_pub}, parent_key_index {parent_key_index} issuer_address {issuer_address}")
    transfer_asset_result =  await submit_transfer_asset(request.app,
                        parent,
                        issuer_address,
                        receiver_address,
                        expired_on=request.json["expired_on"])

    return issuer_address, receiver_address, transfer_asset_result
"""
