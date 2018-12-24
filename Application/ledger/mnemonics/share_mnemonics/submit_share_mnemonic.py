




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
from encryption.symmetric import generate_aes_key, aes_encrypt
from transactions.extended_batch import  multi_transactions_batch

import aiohttp
import asyncio
import binascii
from ledger import messaging
from errors.errors import ApiBadRequest, ApiInternalError
from encryption.signatures import ecdsa_signature
from db.share_mnemonic import store_share_mnemonics, update_shared_secret_array
import coloredlogs, logging
coloredlogs.install()
from protocompiled import payload_pb2


async def share_mnemonic_batch_submit(app, requester_address, user_id,
                            user_accounts, secret_shares, nth_keys_data):
    """
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
            await asyncio.gather(*[
                    store_share_mnemonics(app, trans)
                    for trans in new_list


            ])
        ##updating shared_secret array of the users present in the database,
        ##with the ownership key of every transaqction, address of the users
        ##to whoim these transaction were addressed.
        await update_shared_secret_array(app, user_id, [_t["ownership"] for _t in new_list])
        return True

    except (ApiBadRequest, ApiInternalError) as err:
        #await auth_query.remove_auth_entry(request.app.config.DB_CONN, request.json.get('email'))
        logging.error(f"Error in share_mnemonic_batch_submit {err}")
        raise err
        return False
    return



async def submit_share_mnemonic(app, requester_address, account,
                secret_share, index, private_key):

    """
    Args:
        requester_address(str): The user who wants to share the mnemonic
        account(dict): The blockchain state of the user to whom this user wants to
                share the mnemonic
        secret_share (str): One share of the encrypted mnemonic of the user out of many
            others which will be shared with the user represented by account.
        index(int): ranom index generated from the user mnemonic at which a new
            shared_mnemonic address will be generated at which this share of the mnemonic
            will be stored after encrypting it with a random AES key and encrypting AES
            key with the public key of the user represented but the account.
        private_key(str): private key of the requested generated from its mnemonic
            present at the index.
    """
    acc_signer=create_signer(private_key)


    ##encrypting the shared mnemonic with users account public key
    ##the return will also be in bytes i.e encrypted_secret_share
    #encrypted_secret_share = pub_encrypt(secret_share, account["public"])

    #logging.info(encrypted_secret_share)
    #secret_share = binascii.hexlify(encrypted_secret_share)


    key = generate_aes_key(16) ##this is in bytes
    ciphertext, tag, nonce = aes_encrypt(key, secret_share)
    ciphertext = b"".join([tag, ciphertext, nonce])
    ##The AES_GCM encrypted file content
    encryptes_secret_share = binascii.hexlify(ciphertext).decode()

    ##Encrypting AES key with the child public key, output will ne hex encoded
    ##encryted AES key
    encrypted_key = encrypt_w_pubkey(key, account["public"])

    nonce = random.randint(2**20, 2**30)
    ##nonce signed by zerothprivate key and in hex format
    signed_nonce = ecdsa_signature(private_key, nonce)
    nonce_hash= hashlib.sha512(str(nonce).encode()).hexdigest()


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
                        "idx": index,
                        "created_on": route_utils.indian_time_stamp()
                        "nonce": nonce,
                        "signed_nonce": signed_nonce,
                        "nonce_hash": nonce_hash
                        }


    inputs = [in_data["requester_address"],
                addresser.shared_secret_address(
                    in_data["txn_key"].get_public_key().as_hex(), in_data["idx"])
                ]
    outputs = [in_data["requester_address"],
            addresser.shared_secret_address(
                in_data["txn_key"].get_public_key().as_hex(), in_data["idx"])

                ]

    payload = payload_pb2.CreateShareSecret(
            secret = encryptes_secret_share,
            active = False,
            ownership = account["address"],
            secret_hash= hashlib.sha512(secret_share.encode()).hexdigest(),,
            key=encrypted_key,,
            role= "USER",
            idx=index,
            created_on=  route_utils.indian_time_stamp(),
            nonce=nonce,
            signed_nonce=signed_nonce,
            nonce_hash=nonce_hash
            )



    instance = SendTransactions(app.config.REST_API_URL, app.config.TIMEOUT)
    transaction_id, transaction = instance.share_mnemonic_transaction(
                            txn_key=acc_signer, batch_key=app.config.SIGNER,
                            inputs=inputs, outputs=outputs, payload=payload)

    transaction_id, transaction= await __send_share_mnemonic(**transaction_data)
    shared_secret_address = addresser.shared_secret_address(
        acc_signer.get_public_key().as_hex(), index)

    [transaction_data.pop(key) for key in ["config", "txn_key", "batch_key"]]
    transaction_data.update({"transaction_id": transaction_id,
                            "transaction": transaction,
                            "shared_secret_address": shared_secret_address})

    return transaction_data


async def share_mnemonic_db():
