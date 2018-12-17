

import ledger.utils as ledger_utils
from remotecalls import remote_calls
from assets_api import amazon_s3
import binascii
import asyncio
from encryption import utils as encryption_utils
from addressing import addresser
from encryption import asymmetric
from encryption import symmetric
from encryption import signatures
import base64
import time
import random
from db import accounts_query
from db import assets_query
from db import transfer_assets_query
from  ledger import deserialize_state
from .send_transfer_asset import send_transfer_asset
import assets_api.utils as upload_utils
from errors.errors import AssetError
from accounts_api import userapis
import coloredlogs, logging
coloredlogs.install()
import ledger.assets.utils as asset_utils



async def submit_transfer_asset(app, requester, issuer_address, receiver_address,
            expired_on):

    ##decrypting issuer mnemonic
    logging.info("Enter into Transfer asset")
    f = await userapis.SolveAccount(requester, app)
    decrypted_mnemonic = f.decrypted_mnemonic

    logging.info(f"Requester Mnemonic is {decrypted_mnemonic}")
    instance = await userapis.SolveAddress(issuer_address, app.config.REST_API_URL)

    ##getting issuer public key and the index at which this asset was created
    if instance.type != "CREATE_ASSET":
        raise AssetError("Not a valid issuer address")

    issuer_asset = instance.data
    issuer_asset_public_key, issuer_asset_idx = \
                issuer_asset["public"], issuer_asset["idx"]

    instance = await userapis.SolveAddress(receiver_address, app.config.REST_API_URL)

    if instance.type != "CREATE_ASSET":
        raise AssetError("Not a valid receiver address")
    receiver_asset = instance.data


    logging.info(f"Deserialized receiver asset <<{issuer_asset}>>")

    ##checking is issuer asset is empty or not, empty assets cant be transffered
    if not issuer_asset["file_name"] or not issuer_asset["file_hash"]:
        logging.error("Empty assets cannot be transffered")
        raise AssetError("Empty assets cannot be transffered")

    ##Check if the asset had been transffered to the issuer i.e issets which were
    ###not created by the issuer cant be transffered to other users
    if issuer_asset.get("ownership_received"):
        message= f"This asset is not owned by the user but \
                        received from {issuer_asset['parent_address']}"
        logging.error(message)
        raise AssetError(message)



    ##checking if receiver_asset is empty or not, non empty assets couldnt receive
    ##assets
    if receiver_asset.get("file_name") or receiver_asset.get("file_hash"):
        logging.error("Non empty assets cannot be a receiver")
        raise AssetError("Non empty assets cannot be a receiver")

    ##get issuer keys from the GOAPI_URL, private key corresponding to the
    ##random index public key at which the asset was floated
    issuer_keys = await remote_calls.key_index_keys(app, decrypted_mnemonic,
                                                        [issuer_asset_idx, 0])


    issuer_zeroth_priv, issuer_zeroth_pub = \
                    issuer_keys[str(0)]["private_key"], \
                        issuer_keys[str(0)]["public_key"]


    issuer_nth_priv, issuer_nth_pub = issuer_keys[str(issuer_asset_idx)]["private_key"], \
                            issuer_keys[str(issuer_asset_idx)]["public_key"]

    ##check if issuer n th public key is exactly the public key mentioned in the
    ##asset transaction present on the blockchain, this also checks whether
    ##the requester is actually the owner of the asset
    if issuer_nth_pub != issuer_asset_public_key:
        logging.error("This asset address is not owned by the issuer")
        raise AssetError("This asset address is not owned by the issuer")

    ##decrypting file data stored ob the issuer asset address, this can be
    ##done by issuer private key present on the nth index
    data = await asset_utils.decrypt_file_data(issuer_asset["key"], issuer_asset["url"],
                        issuer_asset["file_hash"], issuer_nth_priv)

    ##TODO: check file_hash
    file_data = {"data": data, "file_name": issuer_asset["file_name"],
                    "file_hash": issuer_asset["file_hash"]}

    ##encrypting again with the public key present at the receiver_asset_address
    key, encrypted_key, s3_url, encrypted_s3_url = \
        await asset_utils.encrypt_file_data(None, receiver_asset["public"], app.config,
            file_data)

    logging.info(f"This is the key {key} , encrypted_key{encrypted_key} \
                and the s3_url {s3_url}")
    master_key, master_url = await asset_utils.master_url_n_key(app.config.ADMIN_ZERO_PUB,
                                key, s3_url)


    ##Now this transaction should be signed by user

    create_asset_signer = ledger_utils.create_signer(issuer_nth_priv)

    ##for added security we will send a nonce signed by issuer account
    ##private key
    nonce = random.randint(2**20, 2**30)
    ##nonce signed by zerothprivate key and in hex format
    hex_signatures = signatures.ecdsa_signature(issuer_zeroth_priv, nonce)



    transaction_data= {"config": app.config,
                    "txn_key":create_asset_signer, "batch_key": app.config.SIGNER,
                    "key": encrypted_key,
                    "url": encrypted_s3_url,
                    "time": int(time.time()),
                    "indiantime": upload_utils.indian_time_stamp(),
                    "file_name": issuer_asset["file_name"],
                    "file_hash": issuer_asset["file_hash"],
                    "expired_on": expired_on,
                    "master_key": master_key,
                    "master_url": master_url,
                    "scope": issuer_asset["scope"],
                    "receiver_address": receiver_address,
                    "issuer_address": issuer_address,
                    "issuer_pub": issuer_nth_pub,
                    "issuer_zero_pub": issuer_zeroth_pub,
                    "signed_nonce": hex_signatures,
                    "nonce": nonce,
                    "issuer_child_zero_pub": issuer_asset.get("child_zero_pub"),
                    }

    logging.info(transaction_data)
    transaction_ids, batch_id = await send_transfer_asset(**transaction_data)

    if transaction_ids:
        ##just because signatures are in bytes
        signed_nonce = transaction_data["signed_nonce"].decode()
        logging.info("Create Transaction has been created successfully")
        ##which imlies the transaction has been submitted successfully,
        ##now all the changes that are required to be done on the databse can
        ##be done
        ##Update users create_asset_idxs key on users entry will be updated by
        ## whomever will call this, because update can happend on pending_users
        transaction_data.update({"transaction_id": transaction_ids[0],
                            "batch_id": batch_id, "signed_nonce": signed_nonce})

        [transaction_data.pop(field) for field in ["config", "txn_key", "batch_key"]]
        await transfer_assets_query.store_transfer_assets(app, transaction_data)
        await assets_query.update_issuer_asset(app, issuer_address, transaction_data)
        await assets_query.update_receiver_asset(app, receiver_address, transaction_data)
        ##TOFO update receiver_address asset and issuer_asset_Address in DB
        return True

    else:
        return False
    return
