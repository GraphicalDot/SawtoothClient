
from routes.route_utils import generate_key_index, indian_time_stamp
from remotecalls import remote_calls



"""
import time
from db import accounts_query
import hashlib
#from encryption import utils as encryption_utils
#from addressing import addresser
#from encryption import asymmetric
#from encryption import symmetric
#import ledger.utils as ledger_utils
from ledger import deserialize_state
from errors import errors
from .__send_share_mnemonic import __send_share_mnemonic
from addressing import addresser
from routes import route_utils
from encryption.utils import create_signer, encrypt_w_pubkey
from encryption.symmetric import generate_aes_key, aes_encrypt
from transactions.extended_batch import  multi_transactions_batch
import random
import aiohttp
import asyncio
import binascii
from ledger import messaging
from errors.errors import ApiBadRequest, ApiInternalError
from encryption.signatures import ecdsa_signature
from db.share_mnemonic import store_share_mnemonics, update_shared_secret_array
import coloredlogs, logging, json
coloredlogs.install()
from protocompiled import payload_pb2

from ledger.send_transaction import SendTransactions
async def share_mnemonic_batch_submit(app, requester_address, user_id,
                            user_accounts, secret_shares, nth_keys_data):

    Args:
        requester_address(str): The user who is sharing his Mnemonic
        user_id(str): user_id of the user who is sharing the Menmonic
        user_accounts(list of dictionaies): The user accounts present on the
                            the blockchain with whom the user wants to share the mnemonic

        secret_shares(list of str): encrypted mnemonic shamir secret shares
        mth_keys_data(dict with keys as random indexes): The Pub/Priv key pairs
                    generated from the random indexes generated from the user mnemonic
                    who wants to share his/her mnemonic, the pub/priv keys are ecc keys
                    fetched from go_api

    All the trasactions will be packaged into a batch and then will be sumitted to the ledger,
    If one transaction fails, All transaction will fail as per the property
    of hyperledger sawtooth

    Output:
        True if all the trasactions in a batch will be submitted
        False if there is any error

    """
    async with aiohttp.ClientSession() as session:
        transactions = await asyncio.gather(*[
              submit_share_mnemonic(app, requester_address,
                        account, secret_share, int(index), nth_keys_data[index]["private_key"])

            for (account, secret_share, index) in zip(user_accounts, secret_shares,
                                        list(nth_keys_data.keys()))
        ])




    batch_id, batch_bytes = multi_transactions_batch(
                    [e["transaction"] for e in transactions], app.config.SIGNER)


    """
    for e in [e["transaction"] for e in transactions]:
        logging.info(e)
    """

    instance = await SendTransactions(app.config.REST_API_URL, app.config.TIMEOUT)
    await instance.push_n_wait(batch_bytes, batch_id)

    new_list = []
    for trans in transactions:
        trans.update({"batch_id": batch_id, "user_id": user_id})
        ##removing payload
        trans.pop("transaction")
        new_list.append(trans)
        ##For production purpose this code block must be validated
        #for transaction in transactions:
        #    transaction.update({"batch_id": batch_id, "user_id": user_id})
        #   [trasaction.pop(e) for e in "secret_key", "key", "secret_hash"]
        f = await  store_share_mnemonics(app, trans)
        logging.info(f)
    ##updating shared_secret array of the users present in the database,
    ##with the ownership key of every transaqction, address of the users
    ##to whoim these transaction were addressed.
    await update_shared_secret_array(app, user_id, [_t["ownership"] for _t in new_list])
    return True



async def submit_receive_secret(app, requester_state, requester_mnemonic):

    """
    Args:
        requester_state(str): The user state present on the blockchain who wants
            to create a new receive secret address
        requester_mnemonic: decrypted mnemonic of the user
    """


    ##encrypting the shared mnemonic with users account public key
    ##the return will also be in bytes i.e encrypted_secret_share
    #encrypted_secret_share = pub_encrypt(secret_share, account["public"])

    #logging.info(encrypted_secret_share)
    #secret_share = binascii.hexlify(encrypted_secret_share)
    index = generate_key_index(requester_state["receive_secret_idxs"])
    nth_keys = await remote_calls.key_index_keys(app, requester_mnemonic,
                                                        [index, 0])

    nth_priv, nth_pub = nth_keys[str(key_index)]["private_key"], \
                        nth_keys[str(key_index)]["public_key"]


    zeroth_priv, zeroth_pub = nth_keys[str(0)]["private_key"], \
                        nth_keys[str(0)]["public_key"]



    ##to prove that this receive_secret has been created by the user himself,
    ##nonce must be signed by the zeroth private of the account
    nonce = random.randint(2**20, 2**30)
    ##nonce signed by zerothprivate key and in hex format
    signed_nonce = ecdsa_signature(zeroth_priv, nonce)
    nonce_hash= hashlib.sha512(str(nonce).encode()).hexdigest()


    acc_signer=create_signer(nth_priv)

    transaction_data= {"role": requester_state["role"],
                        "active": True,
                        "idx": index,
                        "created_on": indian_time_stamp(),
                        "nonce": nonce,
                        "signed_nonce": signed_nonce,
                        "nonce_hash": nonce_hash,
                        }


    receive_secret_address = addresser.received_secret_address(
        acc_signer.get_public_key().as_hex(), index)

    ##both the inputs and outputs addresses will be the same
    ##requester addresss will be fetched from blockchain and checked if its exists
    ##and the shared_secret_addresses will be appended to its
    addresses = [requester_address, shared_secret_address]
    logging.info(f"addresses are {addresses}")

    payload = payload_pb2.CreateShareSecret(**transaction_data)

    instance = await SendTransactions(app.config.REST_API_URL, app.config.TIMEOUT)
    transaction_id, transaction = await instance.share_mnemonic_transaction(
                            txn_key=acc_signer, batch_key=app.config.SIGNER,
                            inputs=addresses, outputs=addresses, payload=payload)

    transaction_data.update({"transaction_id": transaction_id,
                            "transaction": transaction,
                            "shared_secret_address": shared_secret_address,
                            "signed_nonce": signed_nonce.decode()})

    return transaction_data


async def share_mnemonic_db():
    pass
