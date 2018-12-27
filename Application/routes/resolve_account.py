from errors.errors import ApiBadRequest
from errors.errors import ApiInternalError
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import encryption.utils as encryption_utils
from routes import route_utils

from encryption import key_derivations
from encryption import symmetric
import uuid
import binascii
from remotecalls.remote_calls import generate_mnemonic
from ledger import deserialize_state
from addressing import addresser
from db import accounts_query
from remotecalls import remote_calls

import coloredlogs, logging

coloredlogs.install()


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


class ResolveAccount(aobject):

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

        if self.requester["role"] == "CHILD":
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
        elif self.requester["role"] == "USER":
            self.org_address, self.org_state, self.org_db= \
                            await self.user_details(requester["acc_zero_pub"])
            self.child_address, self.child_state = None, None
            self.role = requester["role"]
            self.child_zero_pub = None
            self.child_user_id = None
            self.zero_pub = self.org_state["public"] ##this will be added as a

        else:
            ##this means the requester is orgnization itself, so its child_user_id
            ## and child_zero_pub is None,
            self.org_address, self.org_state, self.org_db= \
                            await self.org_details(requester["acc_zero_pub"])
            self.child_address, self.child_state = None, None
            self.role = requester["role"]
            self.child_zero_pub = None
            self.child_user_id = None

            self.zero_pub = self.org_state["public"] ##this will be added as a


        self.decrypted_mnemonic = await self.decrypt_mnemonic()
        ##this will populate two calss variables, org_address and org_state




    async def generate_shared_secret_addr(self, number):
        """
        THis will generate shared_Secret addresses,
        Number : int , total number of addresses that will be generated
        """

        #shared_idxs = self.org_state.get("shared_secret")
        idxs = []
        #if shared_idxs:
        #    idxs = shared_idxs

        for _ in range(0, number):
            result = await route_utils.generate_key_index(idxs)
            idxs.append(result)

        return await remote_calls.key_index_keys(self.app, self.decrypted_mnemonic, idxs)


        user_state = await deserialize_state.deserialize_user(
                            self.app.config.REST_API_URL, user_address)

        user_db = await accounts_query.find_on_key(self.app, "user_id",
                                        user_state["user_id"])
        return user_address, user_state, user_db



    async def user_details(self, public):
        user_address = addresser.user_address(
                            public, 0)

        user_state = await deserialize_state.deserialize_user(
                            self.app.config.REST_API_URL, user_address)

        user_db = await accounts_query.find_on_key(self.app, "user_id",
                                        user_state["user_id"])
        return user_address, user_state, user_db

    async def org_details(self, public):
        org_address = addresser.organization_address(
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
            decrypted_mnemonic =  encryption_utils.decrypt_mnemonic_privkey(
                self.org_db["encrypted_admin_mnemonic"],
                self.app.config.ADMIN_ZERO_PRIV)
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
