


import requests
import rethinkdb as ret
from test_static import  USER_REGISTRATION, SHARE_MNEMONIC, LOGIN, GET_OTPS, \
            FORGOT_PASSWORD, ALL_SHARE_SECRETS, EXECUTE_SHARE_SECRET,\
            CREATE_RECEIVE_SECRET, GET_ACCOUNT, GET_RECEIVE_SECRETS,\
            GET_SHARES_ON_RECEIVE_SECRETS

from test_miscelleneous import get_headers, receive_asset_data, revoke_time_stamp
import json
import uuid
import coloredlogs, logging
from faker import Faker
faker = Faker()
coloredlogs.install()

"""
class AssetApis(object):



    @staticmethod
    def decrypt_keys(requester, address):

        headers = get_headers(requester["email"],
                                requester["password"])

        return requests.get(DECRYPT_KEYS,  params={"address":address},
                    headers=headers)


    @staticmethod
    def upload_asset(requester, file_data, scope, expired_on, address):

        headers = get_headers(requester["email"],
                        requester["password"])

        ##creating account for Master organization
        logging.info(f"Pinging on {UPLOAD}")
        if headers:
            return requests.post(UPLOAD,
                data=json.dumps({"file_name": file_data["file_name"],
                    "file_hash": file_data["file_hash"],
                    "base64_file_bytes": file_data["b64_bytes"],
                    "scope": scope,
                    "expired_on": expired_on,
                    "address": address}), headers=headers)
        else:
            return False


    @staticmethod
    def create_asset(requester, file_data, scope, expired_on):
        headers = get_headers(requester["email"],
                        requester["password"])

        if headers:
            return requests.post(CREATE_ASSET,
                data=json.dumps({"file_name": file_data["file_name"],
                    "file_hash": file_data["file_hash"],
                    "base64_file_bytes": file_data["b64_bytes"],
                    "scope": scope,
                    "expired_on": expired_on,
                    }), headers=headers)
        else:
            return False


    @staticmethod
    def get_assets(requester):

        headers = get_headers(requester["email"],
                        requester["password"])

        return requests.get(GET_ASSETS, headers=headers)




    @staticmethod
    def create_receive_asset(requester):
        headers = get_headers(requester["email"],
                        requester["password"])
        _id_, name, at_which_asset_expires, description = receive_asset_data()

        return requests.post(CREATE_RECEIVE_ASSET,
            data=json.dumps({"_id_": _id_, "name": name,
                "at_which_asset_expires": at_which_asset_expires,
                "description": description}),
        headers=headers)

    @staticmethod
    def get_receive_assets(requester):
        headers = get_headers(requester["email"],
                        requester["password"])

        return requests.get(GET_RECEIVE_ASSETS,
        headers=headers)

    @staticmethod
    def create_share_asset(requester, asset_address, receive_asset_address,
                            unique_code):
        headers = get_headers(requester["email"],
                        requester["password"])

        return requests.post(CREATE_SHARE_ASSET,
            data=json.dumps({"asset_address": asset_address,
                "receive_asset_address": receive_asset_address,
                "unique_code": unique_code,
                "revoked_on": revoke_time_stamp(days=0, hours=2),
                "comments": " ".join(faker.paragraphs())}),
        headers=headers)

    @staticmethod
    def get_share_assets(requester):
        headers = get_headers(requester["email"],
                        requester["password"])

        return requests.get(GET_SHARE_ASSETS,
        headers=headers)

"""


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

class SecretAPIS(aobject):


    async def create_receive_secret(self, requester):
        headers = get_headers(requester["email"],
                        requester["password"])
        return requests.post(CREATE_RECEIVE_SECRET,
                    headers=headers)

    async def get_receive_secrets(self, requester):
        headers = get_headers(requester["email"],
                        requester["password"])
        return requests.post(GET_RECEIVE_SECRETS,
                    headers=headers)



    async def get_shares_on_receive_secrets(self, requester, receive_secret_address):
        headers = get_headers(requester["email"],
                        requester["password"])

        data = {"receive_secret_address": receive_secret_address}
        return requests.post(GET_SHARES_ON_RECEIVE_SECRETS,
                    data=json.dumps(data),
                    headers=headers)

    async def execute_share_secret(self, requester, receive_secret_address, share_secret_address):
        headers = get_headers(requester["email"],
                        requester["password"])

        data = {"receive_secret_address": receive_secret_address,
                "share_secret_address": share_secret_address}
        return requests.post(EXECUTE_SHARE_SECRET,
                    data=json.dumps(data),
                    headers=headers)

class AccountApis(aobject):
    async def __init__(self):
        pass

    @staticmethod
    def register_organization(requester, organization):
        headers = get_headers(requester["email"],
                        requester["password"])

        ##creating account for Master organization
        if headers:
            return requests.post(CREATE_ORGANIZATION_ACCOUNT,
                data=json.dumps({"pancard": organization["pancard"],
                    "phone_number": organization["phone_number"],
                    "email": organization["email"],
                    "role": organization["role"],
                    "org_name": organization["org_name"]}), headers=headers)
        else:
            return False


    async def get_otps(self, requester):

        return requests.post(GET_OTPS,
                data=json.dumps({"email": requester["email"],
                        "phone_number": requester["phone_number"]}))




    async def forgot_password(self, requester, otp_email, otp_mobile):

        return requests.post(FORGOT_PASSWORD,
                data=json.dumps({"email": requester["email"],
                        "phone_number": requester["phone_number"],
                        "otp_email": otp_email,
                        "otp_mobile": otp_mobile,
                        "new_password": requester["new_password"]}))


    async def all_share_secrets(self, requester):
        headers = get_headers(requester["email"],
                        requester["password"])

        return requests.get(ALL_SHARE_SECRETS, headers=headers)

    async def get_account(self, requester):
        headers = get_headers(requester["email"],
                        requester["password"])

        return requests.get(GET_ACCOUNT, headers=headers)



    @staticmethod
    def register_child(requester, child):
        headers = get_headers(requester["email"],
                        requester["password"])

        return requests.post("http://localhost:8000/accounts/create_child",
                                data=json.dumps(child), headers=headers)



    @staticmethod
    async def register_user(user):

        return requests.post(USER_REGISTRATION,
                                data=json.dumps(user))

    @staticmethod
    async def share_mnemonic(requester, receive_secret_addresess):
        headers = get_headers(requester["email"],
                        requester["password"])

        data = {"receive_secret_addresess": receive_secret_addresess,
                "minimum_required": 3}
        logging.info(headers)
        return requests.post(SHARE_MNEMONIC,
                                data=json.dumps(data), headers=headers)

    @staticmethod
    def get_children(requester):
        headers = get_headers(requester["email"],
                        requester["password"])
        return requests.get(GET_CHILDREN,
            headers=headers)

    @staticmethod
    def get_organization_account(requester):
        headers = get_headers(requester["email"],
                        requester["password"])
        return requests.get(GET_ORGANIZATION_ACCOUNT,
            headers=headers)

    @staticmethod
    def get_float_accounts(requester):
        headers = get_headers(requester["email"],
                        requester["password"])
        return requests.get(GET_FLOAT_ACCOUNTS,
            headers=headers)

    @staticmethod
    def get_address(address):
        return requests.get(GET_ADDRESS,  params={"address":address})


    @staticmethod
    def change_password(requester, new_password):
        headers = get_headers(requester["email"],
            requester["password"])
        data = {"email": requester["email"],
                "password":requester["password"],
                "new_password": new_password}
        return requests.get(CHANGE_PASSWORD, data=json.dumps(data))
