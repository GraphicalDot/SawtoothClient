

"""
import binascii
import random
import hashlib
from encryption.utils import create_signer, decrypt_w_privkey
from routes.resolve_account import ResolveAccount
from encryption.symmetric import aes_decrypt, aes_encrypt
from encryption.asymmetric import priv_decrypt
from encryption.signatures import ecdsa_signature
from routes.route_utils import indian_time_stamp
from ledger.send_transaction import SendExecuteSecret
"""
import aiohttp
import asyncio
import datetime
import json
import random
import hashlib
from addressing import addresser, resolve_address
from remotecalls import remote_calls
from protocompiled import payload_pb2
from ledger import deserialize_state
from ledger.send_transaction import SendConcludeSecret
from encryption.utils import create_signer
from encryption.signatures import ecdsa_signature
from routes.route_utils import indian_time_stamp


import coloredlogs, verboselogs, logging
verboselogs.install()
coloredlogs.install()
logger = logging.getLogger(__name__)


async def conclude_secret_batch_submit(app, requester, mnemonic):

    ##the share_secret transaction were floated, depending upon the
    ##number of other users, our user has chosen who will have the secret shares
    ##of our users mnemonic

    #every share_secret transaction have ownership, address of other user account
    ## secret hash, hash of the secret_share
    ##key, particular key that was originally created to encrypt a particular share
    ##    of particuar user, this key will be different for every user with whom
    ##     secret share of menmonic was shared

    ##Now, the user has forgotten their password , Now based on their email address,
    ## the user will generate different AES keys, depending upon the number of users
    ##with whom he has shared their menmonic

    """
    Steps:
            Retrive number of users account addresses in the shared_secret array
            of the user,

            Generate that numbers of Scrypt keys from the password wth different salts
            these salts will then be stored in the user accounts, just using these
            salts admin cant decrypt the mnemonic

    """
    ##must be intialized

    requester_address = addresser.user_address(requester["acc_zero_pub"], 0)

    ##get user account from the blokchain, its shared_secret will have all share_secret
    ##addresses
    requester_state = await deserialize_state.deserialize_user(app.config.REST_API_URL, requester_address)

    ##allt he shared_secret_addresses for the user
    share_secret_addresses = requester_state["share_secret_addresses"]

    ##Deserializing all the shared_secret transaction present on the blockchain
    ## i.e all the data corresponding to the share_secret_addresses list of addresses
    async with aiohttp.ClientSession() as session:
            share_secret_transactions= await asyncio.gather(*[
                deserialize_state.deserialize_share_secret(app.config.REST_API_URL, address)
                     for address in share_secret_addresses
        ])


    indexes = [e["idx"] for e in share_secret_transactions]
    indexes.append(0)
    nth_keys = await remote_calls.key_index_keys(app, mnemonic, indexes)

    zeroth_priv, zeroth_pub = nth_keys[str(0)]["private_key"], nth_keys[str(0)]["public_key"]


    for share_secret_state in share_secret_transactions:
        logger.info(nth_keys[str(share_secret_state["idx"])]["private_key"])

    async with aiohttp.ClientSession() as session:
        transactions = await asyncio.gather(*[
              submit_conclude_secret(app, requester_address, share_secret_state,
              zeroth_priv, nth_keys[str(share_secret_state["idx"])]["private_key"])
                for share_secret_state in share_secret_transactions
        ])



    logger.info(nth_keys)


    instance = await SendConcludeSecret(app.config.REST_API_URL, app.config.TIMEOUT)
    batch_id, batch_list_bytes = await instance.push_batch([e["transaction"] for e in transactions], app.config.SIGNER)

    """
    index = receive_secret.data["idx"]
    nth_keys = await remote_calls.key_index_keys(request.app, requester_mnemonic,
                                                        [index, 0])
    ##now every share_Secret transaction as a key called as ownership which is
    ##actually an addresss of the receive_Secret transaction, Now appending
    ##public key of that receive_Secret transaction to the transaction data
    for transaction in share_secret_transactions:
        receive_secret = await deserialize_state.deserialize_receive_secret(app.config.REST_API_URL,
                                transaction["ownership"])
        transaction.update({"owner_public": receive_secret["public"]})



    async with aiohttp.ClientSession() as session:
        transactions = await asyncio.gather(*[
              submit_activate_secret(app, transaction, password)
                for transaction in share_secret_transactions
        ])


    instance = await SendActivateSecret(app.config.REST_API_URL, app.config.TIMEOUT)
    batch_id, batch_list_bytes = await instance.push_batch([e["transaction"] for e in transactions], app.config.SIGNER)


    try:
        for transaction in transactions:
            transaction.update({"batch_id": batch_id, "user_id": requester["user_id"]})
            await db_instance.update_reset_key(app, transaction)

    except Exception as e:
        logging.error(e)
        raise CustomError(e)
    return True
    """


async def submit_conclude_secret(app, requester_address, share_secret_state, zeroth_priv, private_key):
    """
    Args:
        share_secret_address: desrialize share_secret transaction data on share_secret address
        created from the random index for the user
    """

    acc_signer=create_signer(zeroth_priv)

    nonce = random.randint(2**20, 2**30)
    ##nonce signed by zerothprivate key and in hex format
    signed_nonce = ecdsa_signature(private_key, nonce)
    user_signed_nonce = ecdsa_signature(zeroth_priv, nonce)
    nonce_hash= hashlib.sha512(str(nonce).encode()).hexdigest()


    ##ON the processor side, signed_nonce will be checked against admin account
    ##public key

    ##this is required as this will add to the confidence that this tramsaction
    ##was signed  by the database owners or The ADMIN
    transaction_data= {
                        "user_address": requester_address,
                        "share_secret_address": share_secret_state["address"],
                        "active": False,
                        "timestamp": indian_time_stamp(),
                        "nonce": nonce,
                        "nonce_hash": nonce_hash,
                        "signed_nonce": signed_nonce,
                        "user_signed_nonce": user_signed_nonce,
                        }

    ##transaction["address"] is actually an address of the shared_secret_transaction
    inputs = [requester_address, share_secret_state["address"]]

    outputs = [share_secret_state["address"]]

    payload = payload_pb2.CreateConcludeSecret(**transaction_data)
    instance = await SendConcludeSecret(app.config.REST_API_URL, app.config.TIMEOUT)
    transaction_id, transaction= await instance.create_conclude_secret(
                txn_key=acc_signer, batch_key=app.config.SIGNER,
                inputs=inputs, outputs=outputs, payload=payload)


    transaction_data.update({"transaction_id": transaction_id,
                            "transaction": transaction,
                            })
    logger.info(transaction_data)
    return transaction_data
