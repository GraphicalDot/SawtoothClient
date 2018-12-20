




import time
from db import accounts_query
import hashlib
#from encryption import utils as encryption_utils
#from addressing import addresser
#from encryption import asymmetric
#from encryption import symmetric
#import ledger.utils as ledger_utils
from remotecalls import remote_calls
from ledger import deserialize_state
from errors import errors
from .__send_share_mnemonic import __send_share_mnemonic
from addressing import addresser
from routes import route_utils
from encryption.utils import create_signer, encrypt_w_pubkey
from encryption.asymmetric import pub_encrypt
from encryption.symmetric import generate_aes_key, aes_encrypt
from transactions.extended_batch import  multi_transactions_batch

import aiohttp
import asyncio
import binascii
from ledger import messaging
from errors.errors import ApiBadRequest, ApiInternalError
import coloredlogs, logging
coloredlogs.install()


async def share_mnemonic_batch_submit(app, requester_address, user_accounts, secret_shares, nth_keys_data):
    async with aiohttp.ClientSession() as session:
        transactions = await asyncio.gather(*[
              submit_share_mnemonic(app, requester_address,
                        account, secret_share, int(index), nth_keys_data[index]["private_key"])

            for (account, secret_share, index) in zip(user_accounts, secret_shares,
                                        list(nth_keys_data.keys()))
        ])


    logging.info(transactions)

    batch_id, batch_list_bytes = multi_transactions_batch(
                    [e["transaction"] for e in transactions], app.config.SIGNER)

    logging.info(batch_list_bytes)

    rest_api_response = await messaging.send(
        batch_list_bytes,
        app.config)


    try:
        result = await  messaging.wait_for_status(batch_id, app.config)

    except (ApiBadRequest, ApiInternalError) as err:
        #await auth_query.remove_auth_entry(request.app.config.DB_CONN, request.json.get('email'))
        raise err
        return False, False



async def submit_share_mnemonic(app, requester_address, account,
                secret_share, index, private_key):


    acc_signer=create_signer(private_key)


    ##encrypting the shared mnemonic with users account public key
    ##the return will also be in bytes i.e encrypted_secret_share
    #encrypted_secret_share = pub_encrypt(secret_share, account["public"])

    #logging.info(encrypted_secret_share)
    #secret_share = binascii.hexlify(encrypted_secret_share)


    key = generate_aes_key(16)
    ciphertext, tag, nonce = aes_encrypt(key, secret_share)
    ciphertext = b"".join([tag, ciphertext, nonce])
    ##The AES_GCM encrypted file content
    encryptes_secret_share = binascii.hexlify(ciphertext).decode()

    ##Encrypting AES key with the child public key
    encrypted_key = encrypt_w_pubkey(key, account["public"])




    transaction_data= {"config": app.config,
                        "txn_key": acc_signer,
                        "batch_key": app.config.SIGNER,
                        "ownership": account["address"],
                        "active": False,
                        "secret": encryptes_secret_share,
                        "key": encrypted_key,
                        "secret_hash": hashlib.sha512(secret_share.encode()).hexdigest(),
                        "requester_address": requester_address,
                        "role": "USER",
                        "idx": index
                        }



    transaction_id, transaction= await __send_share_mnemonic(**transaction_data)

    [transaction_data.pop(key) for key in ["config", "txn_key", "batch_key"]]
    transaction_data.update({"transaction_id": transaction_id,
                            "transaction": transaction})

    return transaction_data
