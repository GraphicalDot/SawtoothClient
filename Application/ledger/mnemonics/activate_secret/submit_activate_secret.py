

from ledger import deserialize_state
from addressing import addresser
from db.db_secrets import DBSecrets
from ledger.send_transaction import SendActivateSecret
from encryption.asymmetric import pub_encrypt
from encryption.key_derivations import generate_scrypt_key
from encryption.signatures import ecdsa_signature
from encryption.utils import create_signer
from routes.route_utils import indian_time_stamp
from errors.errors import CustomError, ApiBadRequest, ApiInternalError
from protocompiled import payload_pb2
import aiohttp
import asyncio
import binascii
import random
import hashlib
import coloredlogs, logging
coloredlogs.install()



async def activate_secret_batch_submit(app, requester, password):

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
    db_instance = await DBSecrets(app, table_name="share_secret",
                                        array_name="share_secret_addresses",
                                        )


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



async def submit_activate_secret(app, transaction, password):
    """
    Args:
        transaction: desrialize share_secret transaction data on share_secret address
        created from the random index for the user
    """
    key, salt = generate_scrypt_key(password, 1, None)

    ##the encrypted scrypt key will also be in bytes. this is the scrypt key
    ##which will be encrypted with other users  public key,
    ##The other user will decrypt with their account private key
    ##and also the secret stored on shasred address,
    ##now he will encrypt the unencrypted original secret with this new scrypt
    ##key
    encrypted_key = pub_encrypt(key, transaction["owner_public"])



    acc_signer=create_signer(app.config.ADMIN_ZERO_PRIV)

    nonce = random.randint(2**20, 2**30)
    ##nonce signed by zerothprivate key and in hex format
    signed_nonce = ecdsa_signature(app.config.ADMIN_ZERO_PRIV, nonce)
    nonce_hash= hashlib.sha512(str(nonce).encode()).hexdigest()


    ##ON the processor side, signed_nonce will be checked against admin account
    ##public key

    ##this is required as this will add to the confidence that this tramsaction
    ##was signed  by the database owners or The ADMIN
    admin_address = addresser.organization_address(app.config.ADMIN_ZERO_PUB, 0)
    transaction_data= {
                        "share_secret_address": transaction["address"],
                        "reset_key": binascii.hexlify(encrypted_key),
                        "nonce": nonce,
                        "nonce_hash": nonce_hash,
                        "signed_nonce": signed_nonce,
                        "admin_address": admin_address,
                        "timestamp": indian_time_stamp()
                        }

    ##transaction["address"] is actually an address of the shared_secret_transaction
    inputs = [transaction["address"], admin_address]

    outputs = [transaction["address"], admin_address]

    payload = payload_pb2.CreateActivateSecret(**transaction_data)
    instance = await SendActivateSecret(app.config.REST_API_URL, app.config.TIMEOUT)
    transaction_id, transaction= await instance.create_activate_secret(
                txn_key=acc_signer, batch_key=app.config.SIGNER,
                inputs=inputs, outputs=outputs, payload=payload)


    transaction_data.update({"transaction_id": transaction_id,
                            "transaction": transaction,
                            "key":binascii.hexlify(key).decode(),
                            "salt":  binascii.hexlify(salt).decode(),
                            })



    return transaction_data
