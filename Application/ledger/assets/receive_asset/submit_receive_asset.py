

import ledger.utils as ledger_utils
from remotecalls import remote_calls
from encryption import utils as encryption_utils

#from upload import amazon_s3
#import binascii
#import asyncio
#from encryption import utils as encryption_utils
from addressing import addresser
import coloredlogs, logging
from .send_receive_asset import send_receive_asset
coloredlogs.install()
#import base64
import time
import hashlib
from encryption import signatures
from pprint import pprint

#import json
import assets_api.utils as upload_utils
from db import accounts_query
from db import assets_query, receive_assets_query
#from ledger import deserialize_state
from accounts_api import userapis
import random

async def submit_receive_asset(app, requester,_id_, name, description,
                                                        at_which_asset_expires):
    """
    """
    f = await userapis.SolveAccount(requester, app)
    decrypted_mnemonic = f.decrypted_mnemonic
    logging.info(f"THis is the decrypted mnemonic {decrypted_mnemonic}")
    org_db_entry = f.org_db
    receive_asset_idxs = f.org_state.get("receive_asset_idxs")
    child_user_id = f.child_user_id
    child_zero_pub = f.child_zero_pub
    account_zero_pub = f.zero_pub


    key_index = await ledger_utils.generate_key_index(
                                    array=receive_asset_idxs)

    nth_keys = await remote_calls.key_index_keys(app, decrypted_mnemonic,
                                                        [key_index, 0])

    nth_priv, nth_pub = nth_keys[str(key_index)]["private_key"], \
                        nth_keys[str(key_index)]["public_key"]

    org_priv, org_pub = nth_keys[str(0)]["private_key"], \
                        nth_keys[str(0)]["public_key"]

    org_account_address = addresser.create_organization_account_address(
                            account_id=account_zero_pub,
                            index=0)

    instance = await userapis.SolveAddress(org_account_address,
                                app.config.REST_API_URL)
    org_state = instance.data

    ##the transaction will be signed by users nth private key
    create_asset_signer = ledger_utils.create_signer(nth_priv)

    ##we havent included the child_nth_pub in this transaction because it
    ## can be calculated from txn_key on the processor side

    ##for added security we will send a nonce signed by issuer account
    ##private key
    nonce = random.randint(2**20, 2**30)
    nonce_hash = hashlib.sha224(str(nonce).encode()).hexdigest()
    ##nonce signed by zerothprivate key and in hex format
    hex_signatures = signatures.ecdsa_signature(org_priv, nonce)

    receive_asset_address = addresser.receive_asset_address(
                        asset_id=nth_pub,
                        index=key_index)


    unique_code=int("".join(map(str, random.choices(list(range(1, 10)), k=5))))
    unique_code_hash = hashlib.sha224(str(unique_code).encode()).hexdigest()
    encrypted_unique_code = encryption_utils.encrypt_w_pubkey(str(unique_code).encode(), nth_pub)
    encrypted_admin_unique_code = encryption_utils.encrypt_w_pubkey(str(unique_code).encode(),
                app.config.ADMIN_ZERO_PUB)


    transaction_data= {"config": app.config,
                    "txn_key":create_asset_signer, "batch_key": app.config.SIGNER,
                    "_id_": _id_,
                    "time": int(time.time()),
                    "indiantime": upload_utils.indian_time_stamp(),
                    "idx": key_index,
                    "at_which_asset_expires": at_which_asset_expires,
                    "org_name": org_state["org_name"],
                    "org_address": org_account_address,
                    "org_zero_pub": org_pub,
                    "org_role": org_state["role"],
                    "receive_asset_details": {"name": name, "description": description},
                    "child_zero_pub":  child_zero_pub,
                    "signed_nonce": hex_signatures,
                    "nonce": nonce,
                    "nonce_hash": nonce_hash,
                    "unique_code_hash": unique_code_hash,
                    "encrypted_unique_code": encrypted_unique_code,
                    "encrypted_admin_unique_code":encrypted_admin_unique_code
                    }

    logging.info(f"THis is the transaction data in receive_asset")
    logging.info(pprint(transaction_data))

    transaction_ids, batch_id = await send_receive_asset(**transaction_data)

    if batch_id:
        [transaction_data.pop(field) for field in ["config", "txn_key",
                                "batch_key"]]
        signed_nonce = transaction_data["signed_nonce"].decode()

        transaction_data.update({
                    "user_id": requester["user_id"],
                    "public": nth_pub,
                    "transaction_id": transaction_ids[0],
                    "batch_id": batch_id,
                    "signed_nonce": signed_nonce,
                    "unique_code": unique_code
            })

        await receive_assets_query.store_receive_assets(app, transaction_data)
        await accounts_query.update_receive_assets_idxs(app,
                    org_db_entry["user_id"], key_index)
        ##if this receive_asset is created by child of the organization
        ##then update the child account receive_asset_idxs array also
        if child_user_id:
            await accounts_query.update_receive_assets_idxs(app,
                    child_user_id, key_index)

            #await accounts_query.update_create_asst_idxs_pending(app,
            #requester["user_id"], key_index)

        return nth_pub, key_index, receive_asset_address
    else:
        logging.error("Create asset Faied, GO to hell Dude!!!!,\
         Kabhi kabhi lagta hai ki bhagwan hone ka bhi kya fayda")
    return
