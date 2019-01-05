import aiohttp
import asyncio
import datetime
import json
import binascii
from asyncinit import asyncinit
from errors import errors
from addressing import addresser, resolve_address
from ledger import deserialize_state
from db.db_secrets import DBSecrets
from encryption import symmetric
from encryption.split_secret import split_mnemonic, combine_mnemonic
from remotecalls.remote_calls import gateway_scrypt_keys
from .submit_conclude_secret import conclude_secret_batch_submit

import coloredlogs, verboselogs, logging
verboselogs.install()
coloredlogs.install()
logger = logging.getLogger(__name__)



@asyncinit
class RecoverSecret(object):

    async def __init__(self, requester, app, new_password):
        self.requester = requester
        self.new_password = new_password
        self.app = app
        self.table_name="share_secret"
        self.array_name="share_secret_addresses"


    async def update_db(self):
        """
        Since the Mnemonic has been decrypted, the new Mnemonic shall be
        encrypted with a new scrypt key generated from the

        """

    async def update_ledger(self, mnemonic):
        """

        """
        await conclude_secret_batch_submit(self.app, self.requester, mnemonic)



    async def execute(self):
        """
        self.account_address, self.account_state = await self._address_account()
        ##share_secret_addresses for the requester
        self.share_secret_addresses = self.account_state["share_secret_addresses"]
        #Get share secrete states
        self.share_secret_states = await self._fetch_share_secret_states(self.share_secret_addresses)

        ##all the salts for every share_secret_state used to encrypt the reset_secret
        secret_states_with_salts = await self._reset_salts_activate_secret(self.share_secret_states)

        ##these are the keys on which individua secret_addresses reset_secrets
        ##was encrypted, keys will be a list of lists with each element has
        ## key and then salt
        key_salt_array= await asyncio.gather(*[
                    gateway_scrypt_keys(self.app, self.new_password, 1, secret_state["reset_salt"])
                         for secret_state in secret_states_with_salts
                ])

        ##this will be a dict with keys as receive_secret address and their
        ##corresponding decrypted resetsecrets
        shares = await self._decrypting_reset_secrets(secret_states_with_salts, key_salt_array)

        ##this is list of dicts, with each dict having two keys
        ##reset_secret_address and the salt, the salt is the salt which is used with
        ##scrypt key to encrypt the shares before distrbuting it to receive_secret_addresses.
        email_salts = await self._email_salts()

        for e in email_salts:
            value = shares[e["receive_secret_address"]]
            value.append(e["salt"])

        keys= await asyncio.gather(*[
                gateway_scrypt_keys(self.app, self.requester["email"], 1, salt)
                    for (secret, salt) in shares.values()
            ])

        pots = []
        for ((key, salt1), (secret, salt2)) in zip(keys, shares.values()):
            logger.success(f"key={key}, salt1={salt1}, salt={salt2}, secret={secret}")
            pots.append([key, salt1, secret])

        decrypted_mnemonic = combine_mnemonic(pots)
        logger.success(f"Decrypted Menmonic is {decrypted_mnemonic}")
        """

        decrypted_mnemonic="velvet develop awful post stool road tray odor entry kind forest often explain rival diagram scale curious fit sock room exhibit direct acquire hope"
        await self.update_ledger(decrypted_mnemonic)

        return decrypted_mnemonic


    async def _address_account(self):
        """
        Find address and account of the requester based on their role,
        the address and their blockchain state will be different for the
        user and organization role.

        """
        if self.requester["role"] == "USER":
            account_address = addresser.user_address(
                                        self.requester["acc_zero_pub"], 0)
            account_state = await deserialize_state.deserialize_user(
                                    self.app.config.REST_API_URL,
                                    account_address)

        else:
            logger.error("Not implemented yet")
            raise errors.ApiInternalError("This functionality is not implemented yet")

        return account_address, account_state

    async def _fetch_share_secret_states(self, share_secret_addresses):
        """
        Fetch al the share_secret_addresses present in the user share_secret_addresses
        array of the user or orgnization account.
        Args:
            share_secret_addresses: array of share_secret_addresses for the user
        Returns:
            share_secrets: all the share_secrets present on the ledger corresponding
                        to the share_secret_addresses array
        """

        async with aiohttp.ClientSession() as session:
            share_secrets= await asyncio.gather(*[
                deserialize_state.deserialize_share_secret(
                        self.app.config.REST_API_URL, address)
                    for address in share_secret_addresses
            ])

        return share_secrets


    async def _reset_salts_activate_secret(self, share_secret_states):
        """
        The share_secret_addresses have secret key on the ledger.
        When the user forgets their password, they float a activate_secret
        transactions in which a new AES key is generated from SCRYPT algorithm ,
        the new password wil be used for this scrypt algo and a randomly generated
        salt,
        this salt is then stored with each shared secret
        Args:
            share_secret_states: a list of share_secret transaction present on the
                ledger, since they have been fecthed from deserialize_state, they will
                all have a new entry address, which is the address of share_secret
                transactions

        Return:
            share_secret_states: same as args, but will have one more key,
                which is the reset_salt
        """
        db_instance = await DBSecrets(self.app, table_name=self.table_name,
                                    array_name=self.array_name)
        for share_secret in share_secret_states:
            ##this will fetch share_secret_address key with value
            ## as the address of the share_secret_transaction ,
            ##and the keys which will be plucked are reset_bare_key etc
            ##the table from which they will be fecthed is self.table_name
            _d = await db_instance.get_fields("share_secret_address",
                    share_secret["address"],
                    ["reset_salt"])
            share_secret.update({"reset_salt": _d["reset_salt"]
                            })
        return share_secret_states


    async def _decrypting_reset_secrets(self, share_secret_states, key_salt_array):
        """
        User when activating the secret recovery process, Gives a new password,
        from which new scrypt keys generated with salts, these keys then encrypted with
        receive_secrets transaction public keys, The owners of these receive_secret
        transaction decrypt these keys and the secret share with the prviate keys,
        and encrypt the secret again with this new scrpt key

        Args:
            key_salt_array: list of lists with each as hex encoded key and salt
            share_secret_states: correspoding share_secret transactions where
                each enerty has reset_secret key which is encrypted with the
                scrypt key generate from the new pasdsword of the user and the salt
                is present in the key_salt_array
        """
        shares = {}
        for (share_secret_state, key_salt) in zip(share_secret_states, key_salt_array):
            one_salt = binascii.unhexlify(share_secret_state["reset_salt"])
            reset_secret = binascii.unhexlify(share_secret_state["reset_secret"])
            #scrypt_key, _ = key_derivations.generate_scrypt_key(request.json["password"], 1, salt=one_salt)
            scrypt_key, _ = key_salt


            scrypt_key = binascii.unhexlify(scrypt_key.encode())

            de_org_secret = symmetric.aes_decrypt(scrypt_key, reset_secret)
            logger.success(f"Secret share from share_secret address {share_secret_state['address']} been decrypted")
            shares.update({share_secret_state["ownership"]: [de_org_secret]})

            #received_result =await get_addresses_on_ownership(request.app, address)
        #logging.info(shares)
        return shares


    async def _email_salts(self):
        """
        Before deistributing to the share_secret addresses, the menmonic was split
        using shamir secreT

        After splitting, each share is then encrypted with the scrypt key generated
        from the requester email,
        The salts are present in the requester database netry woth key
        org_mnemonic_encryption_salts
        """

        return self.requester["org_mnemonic_encryption_salts"]
