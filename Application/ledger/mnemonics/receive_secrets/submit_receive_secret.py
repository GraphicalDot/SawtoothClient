
from routes.route_utils import generate_key_index, indian_time_stamp
from remotecalls import remote_calls
from ledger.send_transaction import SendReceiveSecret
import coloredlogs, logging, json
coloredlogs.install()
import hashlib
import random
from encryption.signatures import ecdsa_signature
from encryption.utils import create_signer
from addressing import addresser
from protocompiled import payload_pb2
from asyncinit import asyncinit
from db import db_secrets
from errors.errors import ApiInternalError
"""
import time
from db import accounts_query
#from encryption import utils as encryption_utils
#from addressing import addresser
#from encryption import asymmetric
#from encryption import symmetric
#import ledger.utils as ledger_utils
from ledger import deserialize_state
from errors import errors
from .__send_share_mnemonic import __send_share_mnemonic
from routes import route_utils
from encryption.symmetric import generate_aes_key, aes_encrypt
from transactions.extended_batch import  multi_transactions_batch
import random
import aiohttp
import asyncio
import binascii
from ledger import messaging
from errors.errors import ApiBadRequest, ApiInternalError
from db.share_mnemonic import store_share_mnemonics, update_shared_secret_array
"""

async def submit_receive_secret(app, requester_user_id, requester_state,
                                requester_address, requester_mnemonic):

    """
    Args:
        requester_state(str): The user state present on the blockchain who wants
            to create a new receive secret address
        requester_mnemonic: decrypted mnemonic of the user
    """


    index = await generate_key_index(requester_state.get("receive_secret_idxs"))
    logging.info(index)
    nth_keys = await remote_calls.key_index_keys(app, requester_mnemonic,
                                                        [index, 0])

    nth_priv, nth_pub = nth_keys[str(index)]["private_key"], \
                        nth_keys[str(index)]["public_key"]


    zeroth_priv, zeroth_pub = nth_keys[str(0)]["private_key"], \
                        nth_keys[str(0)]["public_key"]



    ##to prove that this receive_secret has been created by the user himself,
    ##nonce must be signed by the zeroth private of the account
    nonce = random.randint(2**20, 2**30)
    ## nonce signed by zerothprivate key and in hex format
    signed_nonce = ecdsa_signature(zeroth_priv, nonce)
    nonce_hash= hashlib.sha512(str(nonce).encode()).hexdigest()


    acc_signer=create_signer(nth_priv)

    transaction_data= {"role": requester_state["role"],
                        "active": True,
                        "created_on": indian_time_stamp(),
                        "nonce": nonce,
                        "signed_nonce": signed_nonce,
                        "nonce_hash": nonce_hash,
                        "requester_address": requester_address,
                        "idx": index,
                        }


    receive_secret_address = addresser.receive_secret_address(
        acc_signer.get_public_key().as_hex(), index)

    ##both the inputs and outputs addresses will be the same
    ##requester addresss will be fetched from blockchain and checked if its exists,
    ##The receive_secret idx will be appended to the array fo account

    addresses = [requester_address, receive_secret_address]
    logging.info(f"addresses are {addresses}")

    payload = payload_pb2.CreateReceiveSecret(**transaction_data)

    instance = await SendReceiveSecret(app.config.REST_API_URL, app.config.TIMEOUT)
    transaction_id, transaction = await instance.push_receive_secret(
                            txn_key=acc_signer, batch_key=app.config.SIGNER,
                            inputs=addresses, outputs=addresses, payload=payload)

    transaction_data.update({"transaction_id": transaction_id,
                            "transaction": transaction,
                            "signed_nonce": signed_nonce.decode()})

    db_instance = await DBReceiveSecret(app,
                                    app.config.DATABASE["receive_secret"],
                                    "receive_secret_idxs")

    await db_instance.store_receive_secrets(requester_user_id, transaction_data)
    await db_instance.update_user_receive_secret(requester_user_id, index)

    return transaction_data





@asyncinit
class DBReceiveSecret(object):
    async def __init__(self, app, table_name, array_name):
        #self.val = await self.deferredFn(param)
        self.app = app
        self.table_name = table_name
        self.array_name = array_name
        self.user_table = app.config.DATABASE["users"]

    async def store_receive_secrets(self, user_id, data):
        try:
            result = await db_secrets.store_data(self.app, self.table_name, user_id, data)
        except Exception as e:
            msg = f"Storing receive secreates failed with an error {e}"
            logging.error(msg)
            raise ApiInternalError(msg)
        logging.info(f"Store receive secret successful with messege {result}")
        return result

    async def update_user_receive_secret(self, user_id, index):
        try:
            result = await db_secrets.update_array_with_index(self.app, self.user_table,
                            user_id, self.array_name, index)

        except Exception as e:
            msg = f"Updating receive secret array of user failed with {e}"
            logging.error(msg)
            raise ApiInternalError(msg)
        logging.info(f"Updating  receive secret arr o user sucessful with {result}")
        return result
