




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
import coloredlogs, logging, json
coloredlogs.install()
from protocompiled import payload_pb2

from ledger.send_transaction import SendTransactions
from db.db_secrets import DBSecrets


async def share_secret_batch_submit(app, requester, receive_secrets,
                                                secret_shares, nth_keys_data):
    """
    Args:
        requester(dict): db entry of the user who is sharing the Menmonic
        receive_secrets(list of dictionaies): The user accounts present on the
                            the blockchain with whom the user wants to share the mnemonic
        secret_shares(list of str): encrypted mnemonic shamir secret shares
        mth_keys_data(dict with keys as random indexes): The Pub/Priv key pairs
                    generated from the random indexes generated from the user mnemonic
                    who wants to share his/her mnemonic, the pub/priv keys are ecc keys
                    fetched from go_api
    All the trasactions will be packaged into a batch and then will be submitted to the ledger,
    If one transaction fails, All transaction will fail as per the property
    of hyperledger sawtooth
    Output:
        True if all the trasactions in a batch will be submitted
        False if there is any error
    """

    if requester["role"] == "USER":
        requester_address = addresser.user_address(requester["acc_zero_pub"], 0)
    else:
        logging.error("NOt implemented yet")

    async with aiohttp.ClientSession() as session:
        transactions = await asyncio.gather(*[
              submit_share_secret(app, requester, requester_address,
                        receive_secret, secret_share, int(index), nth_keys_data[index]["private_key"])

            for (receive_secret, secret_share, index) in zip(receive_secrets, secret_shares,
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



    ##must be intialized
    db_instance = await DBSecrets(app, table_name="share_secret",
                                        array_name="share_secret_addresses",
                                        )


    new_list = []
    for trans in transactions:
        trans.update({"batch_id": batch_id, "user_id": requester["user_id"]})
        ##removing payload
        trans.pop("transaction")
        new_list.append(trans)
        ##For production purpose this code block must be validated
        #for transaction in transactions:
        #    transaction.update({"batch_id": batch_id, "user_id": user_id})
        #   [trasaction.pop(e) for e in "secret_key", "key", "secret_hash"]
        await db_instance.store(requester["user_id"], trans)
        await db_instance.update_array_with_value(
                                requester["user_id"],
                                trans.get("share_secret_address") )
    ##updating shared_secret array of the users present in the database,
    ##with the ownership key of every transaqction, address of the users
    ##to whoim these transaction were addressed.
    return transactions



async def submit_share_secret(app, requester, requester_address, receive_secret,
                secret_share, index, private_key):

    """
    Args:
        requester(dict): The db entry of the user who wants to share the mnemonic
        receive_secret(dict): The blockchain state of the receive_secret addr  to whom
                this user wants to share the mnemonic
                {'role': 'USER',
                'active': True,
                'created_on': '2018-12-28 19:59:14 IST+0530',
                'nonce': 802584806,
                'signed_nonce': '304402204b79ebf02b7.........',
                'nonce_hash': '87b4e684b071956e5598b.........',
                'idx': 1044988318,
                'public': '026f914d49e6321f668139e75.........',
                'address': 'a9d5c23e49419e21d9f5a2ef.........'}
                address is added by deserialize_receive_secret function
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

    ##Encrypting AES key with the public key present at the receive_secret transaction,
    ##output will ne hex encoded encryted AES key
    encrypted_key = encrypt_w_pubkey(key, receive_secret["public"])

    nonce = random.randint(2**20, 2**30)
    ##nonce signed by zerothprivate key and in hex format
    signed_nonce = ecdsa_signature(requester["zeroth_private"], nonce)
    nonce_hash= hashlib.sha512(str(nonce).encode()).hexdigest()


    transaction_data= {"ownership": receive_secret["address"],
                        "active": False,
                        "secret": encryptes_secret_share,
                        "key": encrypted_key,
                        "secret_hash": hashlib.sha512(secret_share.encode()).hexdigest(),
                        "role": "USER",
                        "idx": index,
                        "created_on": route_utils.indian_time_stamp(),
                        "nonce": nonce,
                        "signed_nonce": signed_nonce,
                        "nonce_hash": nonce_hash,
                        "user_address": requester_address #because at the processing side
                                            ##user state needs to be appended with
                                            ##shared_asecret_address on their share_secret_addresses
                        }


    share_secret_address = addresser.shared_secret_address(
        acc_signer.get_public_key().as_hex(), index)

    ##both the inputs and outputs addresses will be the same
    ##requester addresss will be fetched from blockchain and checked if its exists
    ##and the shared_secret_addresses will be appended to its
    inputs = [requester_address, share_secret_address, receive_secret["address"]]
    outputs = [requester_address, share_secret_address]

    payload = payload_pb2.CreateShareSecret(**transaction_data)

    instance = await SendTransactions(app.config.REST_API_URL, app.config.TIMEOUT)
    transaction_id, transaction = await instance.share_mnemonic_transaction(
                            txn_key=acc_signer, batch_key=app.config.SIGNER,
                            inputs=inputs, outputs=outputs, payload=payload)

    transaction_data.update({"transaction_id": transaction_id,
                            "transaction": transaction,
                            "share_secret_address": share_secret_address,
                            "signed_nonce": signed_nonce.decode(),
                            "public": acc_signer.get_public_key().as_hex()})

    return transaction_data
