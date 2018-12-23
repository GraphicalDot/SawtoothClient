




#import time
#from db import accounts_query
#import hashlib
#from encryption import utils as encryption_utils
#from addressing import addresser
#from encryption import asymmetric
#from encryption import symmetric
#import ledger.utils as ledger_utils
#from remotecalls import remote_calls
from ledger.deserialize_state import deserialize_share_secret, deserialize_user

#from errors import errors
from .__send_activate_shares import __send_activate_shares
from addressing import addresser
#from routes import route_utils
from encryption.utils import create_signer

from db.share_mnemonic import get_shared_secret_array, update_reset_key


#encrypt_w_pubkey
from encryption.symmetric import generate_aes_key, aes_encrypt
from encryption.asymmetric import pub_encrypt
from encryption.key_derivations import generate_scrypt_key
from encryption.signatures import ecdsa_signature
from transactions.extended_batch import  multi_transactions_batch

import aiohttp
import asyncio
import binascii
import random
import hashlib
from errors.errors import CustomError
from ledger import messaging
#from errors.errors import ApiBadRequest, ApiInternalError
import coloredlogs, logging
coloredlogs.install()



async def activate_shares_batch_submit(app, requester_account, password):

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
    logging.info("Entered into submit_activate_shares")
    account_addresses = await get_shared_secret_array(app, requester_account["user_id"])


    requester_address = addresser.user_address(requester_account["acc_zero_pub"], 0)

    ##get user account from the blokchain, its shared_secret will have all share_secret
    ##addresses
    requester_state = await deserialize_user(app.config.REST_API_URL, requester_address)

    ##allt he shared_secret_addresses for the user
    share_secrets_addresses = requester_state["shared_secret"]


    ##fetching all the share_secret transactions present on the share_secret_adddresses
    ## from the blockchain
    async with aiohttp.ClientSession() as session:
        share_secret_transactions= await asyncio.gather(*[
            deserialize_share_secret(app.config.REST_API_URL, address)
                 for address in share_secrets_addresses
        ])

    ##based on the data fetched from all the share_secret transaction new ACTIVATE_SECRET
    ##transactions will be created
    async with aiohttp.ClientSession() as session:
        transactions = await asyncio.gather(*[
              submit_activate_shares(app, transaction, password)
                for transaction in share_secret_transactions
        ])





    batch_id, batch_list_bytes = multi_transactions_batch(
                    [e["transaction"] for e in transactions], app.config.SIGNER)

    rest_api_response = await messaging.send(
        batch_list_bytes,
        app.config)


    try:
        result = await  messaging.wait_for_status(batch_id, app.config)
        ##This must be removed in production, since it stores shared_mnemonic

        new_list = []
        for transaction in transactions:
            transaction.update({"batch_id": batch_id, "user_id": user_id})
            ##removing payload
            transaction.pop("transaction")
            new_list.append(transaction)
            ##For production purpose this code block must be validated
            #for transaction in transactions:
            #    transaction.update({"batch_id": batch_id, "user_id": user_id})
            #   [trasaction.pop(e) for e in "secret_key", "key", "secret_hash"]

        async with aiohttp.ClientSession() as session:
            db_results = await asyncio.gather(*[
                    update_reset_key(app, requester_account["user_id"],
                                trans["reset_key"], trans["share_secret_address"])
                    for trans in new_list

            ])
        logging.info(db_results)
    except Exception as e:
        logging.error(e)
        raise CustomError(e)
    return True

async def submit_activate_shares(app, transaction, password):
    """
    Args:
        trasaction: desrialize share_secret transaction data on share_secret address
        created from the random index for the user
    """
    key, salt = generate_scrypt_key(password, 1, None)

    ##the encrypted scrypt key will also be in bytes. this is the scrypt key
    ##which will be encrypted with other users  public key,
    ##The other user will decrypt with their account private key
    ##and also the secret stored on shasred address,
    ##now he will encrypt the unencrypted original secret with this new scrypt
    ##key
    encrypted_key = pub_encrypt(key, transaction["public"])



    acc_signer=create_signer(app.config.ADMIN_ZERO_PRIV)

    nonce = random.randint(2**20, 2**30)
    ##nonce signed by zerothprivate key and in hex format
    signed_nonce = ecdsa_signature(app.config.ADMIN_ZERO_PRIV, nonce)
    nonce_hash= hashlib.sha512(str(nonce).encode()).hexdigest()


    ##ON the processor side, signed_nonce will be checked against admin account
    ##public key

    admin_address = addresser.organization_address(app.config.ADMIN_ZERO_PUB, 0)
    transaction_data= {"config": app.config,
                        "txn_key": acc_signer,
                        "batch_key": app.config.SIGNER,
                        "share_secret_address": transaction["address"],
                        "reset_key": binascii.hexlify(encrypted_key),
                        "nonce": nonce,
                        "nonce_hash": nonce_hash,
                        "signed_nonce": signed_nonce,
                        "admin_address": admin_address,
                        }




    transaction_id, transaction= await __send_activate_shares(**transaction_data)

    [transaction_data.pop(key) for key in ["config", "txn_key", "batch_key"]]
    transaction_data.update({"transaction_id": transaction_id,
                            "transaction": transaction,
                            "key":binascii.hexlify(key), "salt":  binascii.hexlify(salt)})

    return transaction_data
