


from ledger import deserialize_state
import coloredlogs, verboselogs, logging
from addressing import addresser, resolve_address
from remotecalls.remote_calls import gateway_scrypt_keys
from encryption.split_secret import split_mnemonic, combine_mnemonic
from routes.resolve_account import ResolveAccount
from remotecalls import remote_calls
from routes.route_utils import generate_key_index
import aiohttp
import asyncio
import datetime
import json
from db.share_secret import update_mnemonic_encryption_salts

verboselogs.install()
coloredlogs.install()
logger = logging.getLogger(__name__)

from errors.errors import ApiInternalError
from asyncinit import asyncinit
from db.db_secrets import DBSecrets
from .submit_share_secret import share_secret_batch_submit
@asyncinit
class ShareSecret(object):

    async def __init__(self, app, requester, minimum_required, total_shares,
                    receive_secret_addresess):
        self.app = app
        self.requester = requester
        self.minimum_required = minimum_required
        self.total_shares = total_shares
        self.receive_secret_addresses = receive_secret_addresess
        self.total_shares = len(self.receive_secret_addresses)
        self.table_name= "share_secret"
        self.array_name="share_secret_addresses"
        user = await ResolveAccount(self.requester, self.app)
        self.user_address = user.org_address
        self.user_state = user.org_state

        ##if the user is share mnemonic for the first time this will be None
        self.share_secret_addresses = self.user_state.get("share_secret_addresses")

        self.user_mnemonic = user.decrypted_mnemonic
        logger.success(f"Decrypted user mnemonic is {self.user_mnemonic}")


    async def execute(self):
        self.check_minimum_req()
        self.check_total_shares()

        self.is_receive_secrets()

        self.receive_secret_states = await self._receive_secret_states()

        self.nth_keys_data = await self._generate_shared_secret_addr()


        key_salt_array = await self._email_scrypt_keys()

        key_salt_secret_array = await self.split_mnemonic(key_salt_array)

        ##updating receive_Secret_states with sakt, key and the encrypted secret
        self._update_receive_secret_salt(key_salt_secret_array)
        await self._update_user_with_salts()

        ##all the share_secret transaction nonce will be signed by the xeroth
        #private key of the requester so that its authenticatn can be checked
        ##getting zeroth private key of the user

        ##updating requester data dict with zeroth private key of the requester

        zeroth_private_key= await self._get_zeroth_pair()

        self.requester.update({"zeroth_private": zeroth_private_key})

        batch_id, transactions = await share_secret_batch_submit(self.app,
                                                    self.requester,
                                                    self.receive_secret_states,
                                                    self.nth_keys_data)

        await self._results_db(batch_id, transactions)
        return batch_id

    def check_minimum_req(self):
        if self.minimum_required >= 3:
            logger.success("Minimum requirement fulfilled")
        else:
            raise ApiInternalError(f"{__name__} To share passwords minimum 3 \
            users are required")

    def check_total_shares(self):
        if self.minimum_required < len(self.receive_secret_addresses):
            logger.success("Total shares condition fulfilled")
        else:
            raise ApiInternalError("To share passwords minimum 3 \
            users are required")

    def is_receive_secrets(self):
        """
        check if receive secret_addresses are valid receive_secret_addresses

        """
        error_msg = f"{__name__} Not a receive_secret address"
        ##check whether all the receive_secret_addrs are valid
        for addr in self.receive_secret_addresses:
                if "RECEIVE_SECRET" != addresser.address_is(addr)[0]:
                    raise ApiInternalError(error_msg)

    def is_user_receive_secret_address():
        """
        """
        ##TODO, check whether the receive_secret_addresses has any address
        ##which belongs to the user himself/herself.

        pass

    async def _receive_secret_states(self):
        """
        Get receive_secret states from the ledger from the receive_secret_addresses
        """
        async with aiohttp.ClientSession() as session:
            return  await asyncio.gather(*[
                deserialize_state.deserialize_receive_secret(
                                self.app.config.REST_API_URL, address)
                     for address in self.receive_secret_addresses
            ])

    async def _generate_shared_secret_addr(self):
        """
        THis will generate shared_Secret addresses,
        First fetch if there are any already shared_secret_addresses

        required = share_secret_addresses - number

        Three cases arises:
            1. User wants to increase the number of receivers then was already there
                in this case, required will be negative
            2. User wants to decrease the number of number of receivers, in this
                case required will be positive
            3. FIrst time required will be negative
            4. THe number of same, required is ZERO
        """
        ##TODO: update share secret, for example in case 2 is valid, then
        ##all the share_secret_address who arent participating must be made inactive

        ##first time when shre_mnemonic transactions are being floated
        idxs = []
        if not self.share_secret_addresses:
            for _ in range(0, self.total_shares):
                idx = await generate_key_index(None)
                idxs.append(idx)
        else:
            required = len(self.share_secret_addresses) - self.total_shares
            #shared_idxs = self.org_state.get("shared_secret")
            if required < 0:
                ##this implies the the previousl share_secret_addresses are
                ##equal to the reuqired right now
                idxs = [generate_key_index() for _ in range(0, required)]

                for addr in self.share_secret_addresses:
                    ins = await resolve_address.ResolveAddress(addr, self.app.config.REST_API_URL)
                    idxs.append(ins.data["idx"])
            else:
                raise ApiInternalError(f"{__name__} The total shares are less \
                        than secret_addresses present, not implemented yet")
        ##resolving account for the requester to get his decrypted menmonic

        ##On the basis of the length of user_accounts, generate random indexes
        ## from the mnemonic and get the PUBlic/private keys corresponding to these
        ##indxs, these, these addresses will be appended to the

        return await remote_calls.key_index_keys(self.app, self.user_mnemonic, idxs)


    ##will be a list of lists wtih each entry, hex encoded [key, salt]

    async def _email_scrypt_keys(self):
        """
        will be a list of dict with each dict as
        {"key": , "salt": , "secret"}, all three being hex encoded
        """
        async with aiohttp.ClientSession() as session:
            return  await asyncio.gather(*[
                gateway_scrypt_keys(self.app, self.requester["email"], 1, None)
                     for _ in range(0, self.total_shares)
            ])


    async def split_mnemonic(self, key_salt_array):
        """

        Returns:
            of the form
            {"key": key, "salt": salt, "secret": binascii.hexlify(ciphertext)}

        keys= await asyncio.gather(*[
                gateway_scrypt_keys(request.app, user.org_db["email"], 1, e["salt"])
                     for e in key_salt_secrets
            ])

        g = combine_mnemonic(keys, [e["secret"] for e in key_salt_secrets])
        logger.success(g)

        """
        key_salt_secrets = split_mnemonic(key_salt_array,
                        self.user_mnemonic, self.minimum_required,
                        self.total_shares)
        return key_salt_secrets


    def _update_receive_secret_salt(self, key_salt_secrets):
        """
        Assign the salt and the encrypted secrets array to the receive_secret_Addresses
        Now the encrypted samir secret must be assigned to receive_secret addresses
        """

        for (_dict, receive_secret_state) in zip(key_salt_secrets, self.receive_secret_states):
                receive_secret_state.update({
                            "secret": _dict["secret"],
                            "salt": _dict["salt"]})
        return


    async def _get_zeroth_pair(self):
        """
        Fetch zeroth key pair for the requester
        """
        nth_keys = await remote_calls.key_index_keys(self.app,
                    self.user_mnemonic, [0])

        return nth_keys[str(0)]["private_key"]


    async def _update_user_with_salts(self):
        """
        Now we have generated scrypt keys based on the email with the salts.
        For each receive_secret transaction, a scrypt key with salt wads generated

        In the event of receover mnemonic trnasactions, these salts will be required
        to decrypt the recovere mnemonic from the share_secret transactions

        So This method will store the salts with receive_secret_address in the
        user entry in the databasein the users table
        """
        ##upadting user entry in the users table with the salt which was used in
        ##encrypting mnemonic before it was split into shamir secret shares
        salt_array = [{"salt": state["salt"], "receive_secret_address": state["address"]} \
                                    for state in self.receive_secret_states]

        return await update_mnemonic_encryption_salts(self.app,
                                        self.requester["user_id"],
                                        salt_array)
        #index = list(nth_keys_data.keys())[0]

    async def _results_db(self, batch_id, transactions):
        """

        """
        ##must be intialized
        db_instance = await DBSecrets(self.app, table_name=self.table_name,
                                            array_name=self.array_name,
                                            )


        for trans in transactions:
            trans.update({"batch_id": batch_id, "user_id": self.requester["user_id"]})
            ##removing payload stored in the key transaction
            trans.pop("transaction")
            ##For production purpose this code block must be validated
            #for transaction in transactions:
            #    transaction.update({"batch_id": batch_id, "user_id": user_id})
            #   [trasaction.pop(e) for e in "secret_key", "key", "secret_hash"]
            await db_instance.store(self.requester["user_id"], trans)
            await db_instance.update_array_with_value(
                                    self.requester["user_id"],
                                    trans.get("share_secret_address") )
        ##updating shared_secret array of the users present in the database,
        ##with the ownership key of every transaqction, address of the users
        ##to whoim these transaction were addressed.
        return
