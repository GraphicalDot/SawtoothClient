

import ledger.utils as ledger_utils
import ledger.assets.utils as asset_utils
from remotecalls import remote_calls


from addressing import addresser
import json
from encryption import signatures
import base64
import time
import random
from db import accounts_query
from db import assets_query
from db import share_assets_query
from  ledger import deserialize_state
from .send_share_asset import send_share_asset
import assets_api.utils as upload_utils
from errors.errors import AssetError, ApiInternalError, CustomError
import hashlib
import coloredlogs, logging
from accounts_api import userapis
coloredlogs.install()


async def submit_share_asset(app, requester, asset_address,
                        receive_asset_address, unique_code, revoked_on, comments):

    """

        1.check whether asset_address is valid asset address or not
        2. check whether the asset is empty or not
        3.check whether the asset has been transsefred the ownership to someother  empty asset
        4.check whether the requester is the owner of this asset or not
        5.check whether the receiver_asset_address is a valid receive_asset_address or not
        6.check whether at_which_asset_expires is stil valid or hasnt expired
        7.cheque whether the sha_2224 hash of unique code matches with receiver_asset

    """

    f = await userapis.SolveAccount(requester, app)
    decrypted_mnemonic = f.decrypted_mnemonic
    org_state = f.org_state
    logging.info(f"THis is the decrypted mnemonic {decrypted_mnemonic}")
    share_asset_idxs = f.org_state.get("share_asset_idxs")
    child_user_id = f.child_user_id
    child_zero_pub = f.child_zero_pub
    account_zero_pub = f.zero_pub

    unique_code_hash = hashlib.sha224(str(unique_code).encode()).hexdigest()
    if await share_assets_query.find_share_asset(app, asset_address,
                                receive_asset_address):
            raise ApiInternalError("This shared asset has already been done")
    ##checking point 5
    receive_asset_instance = await userapis.SolveAddress(
                            receive_asset_address,
                            app.config.REST_API_URL)


    if receive_asset_instance.type != "RECEIVE_ASSET":
        raise AssetError("receive_asset_address is notreceive asset address")

    if not receive_asset_instance.data["at_which_asset_expires"] > upload_utils.now_time_stamp():
            raise errors.InvalidValidityPeriod("The time to share asset with this \
                    address has been expired")

    if receive_asset_instance.data["unique_code_hash"] !=\
            unique_code_hash:
            raise AssetError("Unique code provided is either wrong or meant for different receiver_address")


    asset_instance = await userapis.SolveAddress(asset_address, app.config.REST_API_URL)
    if asset_instance.type != "CREATE_ASSET":
        raise AssetError("asset_address is not asset address")

    ##check point 2
    if not asset_instance.data["file_name"] or not asset_instance.data["file_hash"]:
        raise AssetError("Empty assets cannot be shared")





    ##decrypting issuer mnemonic

    requester_account_address = addresser.create_organization_account_address(
                            account_id=org_state["public"],
                            index=0
            )


    ##Check if the asset had been transffered to the issuer i.e issets which were
    ###not created by the issuer cant be transffered to other users
    if asset_instance.data.get("ownership_transfer"):
        message= f"This asset which already have been transffered to \
                {issuer_asset.get('ownership_transfer')} can be shared"
        logging.error(message)
        raise AssetError(message)


    key_index = await ledger_utils.generate_key_index(share_asset_idxs)
    logging.info(f"THis is the key index for issuer {key_index}")

    ##at which the asset was created
    asset_index = asset_instance.data["idx"]

    nth_keys = await remote_calls.key_index_keys(app, decrypted_mnemonic,
                                    [0, key_index, asset_index ])


    ##account kets for the issuer
    requester_zeroth_priv, requester_zeroth_pub = \
                    nth_keys[str(0)]["private_key"], \
                        nth_keys[str(0)]["public_key"]


    ##keys at which teh asset which needs to be shared was floated
    create_asset_priv, create_asset_pub = nth_keys[str(asset_index)]["private_key"], \
                            nth_keys[str(asset_index)]["public_key"]


    ##keys at which the shared asset index will be floated
    share_asset_priv, share_asset_pub = nth_keys[str(key_index)]["private_key"], \
                            nth_keys[str(key_index)]["public_key"]




    ##check if issuer n th public key is exactly the public key mentioned in the
    ##asset transaction present on the blockchain, this also checks whether
    ##the requester is actually the owner of the asset
    if create_asset_pub != asset_instance.data.get("public"):
        logging.error("This asset address is not owned by the issuer")
        raise AssetError("This asset address is not owned by the issuer")

    ##decrypting file data stored ob the issuer asset address, this can be
    ##done by issuer private key present on the nth index
    data = await asset_utils.decrypt_file_data(asset_instance.data["key"], asset_instance.data["url"],
                        asset_instance.data["file_hash"], create_asset_priv)

    ##TODO: check file_hash
    file_data = {"data": data, "file_name": asset_instance.data["file_name"],
                    "file_hash": asset_instance.data["file_hash"]}

    ##encrypting again with the public key present at the receiver_asset_address
    key, encrypted_key, s3_url, encrypted_s3_url = \
        await asset_utils.encrypt_file_data(None, receive_asset_instance.data["public"], app.config,
            file_data)

    logging.info(f"This is the key {key} , encrypted_key{encrypted_key} \
                and the s3_url {s3_url}")
    master_key, master_url = await asset_utils.master_url_n_key(app.config.ADMIN_ZERO_PUB,
                                key, s3_url)


    ##Now this transaction should be signed by user

    create_asset_signer = ledger_utils.create_signer(share_asset_priv)

    ##for added security we will send a nonce signed by issuer account
    ##private key
    nonce = random.randint(2**20, 2**30)
    nonce_hash= hashlib.sha224(str(nonce).encode()).hexdigest()
    account_hex_signature = signatures.ecdsa_signature(requester_zeroth_priv, nonce)

    ##nonce must also be signed with the private key at random index at which
    ##create asset is present
    asset_hex_signature = signatures.ecdsa_signature(create_asset_priv, nonce)



    transaction_data= {"config": app.config,
                    "txn_key":create_asset_signer, "batch_key": app.config.SIGNER,
                    "key": encrypted_key,
                    "url": encrypted_s3_url,
                    "master_key": master_key,
                    "master_url": master_url,
                    "time": int(time.time()),
                    "indiantime": upload_utils.indian_time_stamp(),
                    "file_name": asset_instance.data["file_name"],
                    "file_hash": asset_instance.data["file_hash"],
                    "original_asset_address": asset_address,
                    "revoked_on": revoked_on,
                    "comments": comments,
                    "idx": key_index,
                    "account_signature": account_hex_signature,
                    "asset_signature": asset_hex_signature,
                    "nonce": nonce,
                    "nonce_hash": nonce_hash,
                    "to_org_name": receive_asset_instance.data["org_name"],
                    "to_org_address": receive_asset_instance.data["org_address"],
                    "issuer_account_address": requester_account_address,
                    "receive_asset_address": receive_asset_address,
                    "child_zero_pub": child_zero_pub,
                    "unique_code_hash": unique_code_hash,
                    }

    transaction_ids, batch_id = await send_share_asset(**transaction_data)

    if transaction_ids:
        logging.info("Share Transaction has been created successfully")
        ##which imlies the transaction has been submitted successfully,
        ##now all the changes that are required to be done on the databse can
        ##be done
        ##Update users create_asset_idxs key on users entry will be updated by
        ## whomever will call this, because update can happend on pending_users
        share_asset_address = addresser.share_asset_address(
                share_asset_pub,
                key_index)
        account_signature = account_hex_signature.decode()
        asset_signature=asset_hex_signature.decode()
        transaction_data.update({"transaction_id": transaction_ids[0],
                            "batch_id": batch_id,
                            "account_signature": account_signature,
                            "asset_signature": asset_signature,
                            "address": share_asset_address })

        [transaction_data.pop(field) for field in ["config", "txn_key", "batch_key"]]
        await share_assets_query.store_share_asset(app, transaction_data)

        ##now asset must be update with share_with key
        await assets_query.update_issuer_asset_shared(
                            app, asset_address, key_index)
        ##TOFO update receiver_address asset and issuer_asset_Address in DB

        await accounts_query.update_share_asset_idxs(
                    app, org_state["user_id"], key_index)

        if child_user_id:
            await accounts_query.update_share_asset_idxs(
                    app, child_user_id, key_index)


        return share_asset_address

    else:
        return False
    return
