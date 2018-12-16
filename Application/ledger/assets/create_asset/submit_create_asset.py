

import ledger.utils as ledger_utils
from remotecalls import remote_calls
from upload import amazon_s3
import binascii
import asyncio
from encryption import utils as encryption_utils
from addressing import addresser
from encryption import asymmetric
from encryption import symmetric
import coloredlogs, logging
from .send_create_asset import send_create_asset
coloredlogs.install()
import base64
import time
import json
import upload.utils as upload_utils
from db import accounts_query
from db import assets_query
from ledger import deserialize_state
from users import useraccounts
import ledger.assets.utils as asset_utils


async def submit_empty_asset(app, requester, claimed=False):
    """
    claimed : False, Which means this account hasnt been claimed, it doesnt have
            a orgnization_account
            Implies that create_asset_idxs array of float account will be appended
            with key_index rather the orgnization acount create_asset_idxs
    float_accounts cannot create assets, but any other orgnization who have been
    claimed can force float_account to create empty asset, thats why
    for create_asset claimed will be always True.

    Now empty asset can be created by any account, Child, orgnization or
    float_account

    Child account for float_account can't exists

    """

    f = await useraccounts.SolveAccount(requester, app)
    decrypted_mnemonic = f.decrypted_mnemonic
    org_db_entry = f.org_db

    logging.info(f"THis is the decrypted mnemonic {decrypted_mnemonic}")
    create_asset_idxs = f.org_state.get("create_asset_idxs")
    child_zero_pub = f.child_zero_pub
    child_user_id = f.child_user_id
    zero_pub = f.zero_pub

    if not claimed: ##these are required so that create_asset_idxs of float account
                    ##can be apended with key_index
        flt_account_parent_pub =requester["parent_pub"] #exists both in users_table
        flt_account_parent_idx=requester["parent_idx"]
    else:
        flt_account_parent_pub =None #exists both in users_table
        flt_account_parent_idx= None

    key_index = await ledger_utils.generate_key_index(
                                    array=create_asset_idxs)

    nth_keys = await remote_calls.key_index_keys(app, decrypted_mnemonic,
                                                        [key_index])

    nth_priv, nth_pub = nth_keys[str(key_index)]["private_key"], \
                        nth_keys[str(key_index)]["public_key"]


    key=encrypted_key=s3_url=encrypted_s3_url = None


    master_key = master_url = None

    ##the transaction will be signed by users nth private key
    create_asset_signer = ledger_utils.create_signer(nth_priv)

    ##we havent included the child_nth_pub in this transaction because it
    ## can be calculated from txn_key on the processor side



    asset_address = addresser.create_asset_address(
                        asset_id=nth_pub,
                        index=key_index)

    transaction_data= {"config": app.config,
                    "txn_key":create_asset_signer, "batch_key": app.config.SIGNER,
                    "key": None,
                    "url": None,
                    "time": int(time.time()),
                    "indiantime": upload_utils.indian_time_stamp(),
                    "file_name": None,
                    "file_hash":None,
                    "idx": key_index,
                    "master_key": None,
                    "master_url": None,
                    "scope": None,
                    "role": requester["role"],
                    "zero_pub": zero_pub,
                    "is_acc_claimed": claimed,
                    "flt_account_parent_pub": flt_account_parent_pub,
                    "flt_account_parent_idx": flt_account_parent_idx,
                    "child_zero_pub":  child_zero_pub,
                    }

    logging.info(f"THis is the transaction data {transaction_data}")

    transaction_ids, batch_id = await send_create_asset(**transaction_data)

    if batch_id:

        [transaction_data.pop(field) for field in ["config", "txn_key",
                                "batch_key", "is_acc_claimed", "flt_account_parent_pub",
                                "flt_account_parent_idx"]]
        transaction_data.update({
                    "user_id": requester["user_id"],
                    "public": nth_pub,
                    "transaction_id": transaction_ids[0],
                    "batch_id": batch_id,
                    "asset_address": asset_address,
                    "child_zero_pub": child_zero_pub

            })
        await assets_query.store_assets(app, transaction_data)
        if claimed:
            await accounts_query.update_create_asst_idxs(app,
                    org_db_entry["user_id"], key_index)
        else:
            logging.error("Must be a float account")
            await accounts_query.update_create_asst_idxs_pending(app,
                    org_db_entry["user_id"], key_index)

        if child_user_id:
            await accounts_query.update_create_asst_idxs(app,
                child_user_id, key_index)

            #await accounts_query.update_create_asst_idxs_pending(app,
            #requester["user_id"], key_index)

        return nth_priv, nth_pub, key_index, asset_address
    else:
        logging.error("Create asset Faied, GO to hell Dude!!!!,\
         Kabhi kabhi lagta hai ki bhagwan hone ka bhi kya fayda")
    return


async def submit_create_asset(app, requester, file_data):
    """

    Creates an empty asset or asset with data,

    Process:
        Get user Mnemonic
            If user is child,
                    then get the mnemonic of the parent orgnization
            This can be done by getting by fetching org account present on the
            blokchchain constructing org_address from child["parent_pub"]

            Checks:
                1.check if child is actually a valid child by checking if child
                parent_idx is in org_account["child_account_idxs"]
                2. Check child org_name is same is orgnization org_name

            Fecth org entry in the dabase corresponding to the user_id of the
            org in orgnization entry on blokchchain

            NOw decrypt the org menmonic with Admin public key if org is not admin

            Now, get the create_asset_idxs array of the organization from the
            blockchain
        if requester is orgnization:
            Fecth org entry in the dabase corresponding to the user_id of the
            org in orgnization entry on blokchchain

            NOw decrypt the org menmonic with Admin public key if org is not admin

            Now, get the create_asset_idxs array of the organization from the
            blockchain

    A new key_index will be generated at create_asset_idxs,
    From the decrypted_nemonic, Public/Private key pair will be generated at this
    key_index, this will be a asset_address

    NOw, Check if file_Data is there or not, if yes, Encrypt the file data with
    random AES key, and post it on S3,
    Now encrypt both AES key and s3_url with the public key generated at random index

    Now there are two main conditions which needs attention,
        The user who still dont have an orgnization account but only a float_account
        In this case,
            is_claimed
            "flt_account_parent_pub": requester["parent_pub"],
            "flt_account_parent_idx": requester["parent_idx"],
            THese are required because since this is a float_account, on the
            processor side, the key_index will be appended to float_account which
            will be calculated from these two keys

        Th user does have an orgnization account

    The user whom is floating this transaction
    if claimed=False, user havent claimed his/her account


    if claimed=False, the requester["role"] cant be child, as float
    accounts arent allowed to create child roles,
    ADMIN doesnt have float accounts



    "flt_account_parent_pub": None,
    "flt_account_parent_idx": None,
    THese keys are required if the account is float_account, Now since this orgnization
    doesnt have any real account or the account has not been claimed, the create_asset_idxs
    will be appended to create_asset_idxs of float account

    Now since float account can not create new assets, only assets being transffered to them,
    Float account cannot run this function as credentials of float account are debarred from
    accessing this api or this function

    so, only CHILD, AQDMIN or any other orgnixzation who already have alimed their account
    can access this API, which means they have orgnization account, which means
    key_index will be appende to their orgnization account not float_account_idxs,
    Hence these two keys will be none for this function
    """
    logging.info("Enterintosubmitcreateasset")
    f = await useraccounts.SolveAccount(requester, app)
    decrypted_mnemonic = f.decrypted_mnemonic
    org_state = f.org_state
    logging.info(f"THis is the decrypted mnemonic {decrypted_mnemonic}")
    create_asset_idxs = f.org_state.get("create_asset_idxs")
    child_zero_pub = f.child_zero_pub
    child_user_id = f.child_user_id
    zero_pub = f.zero_pub
    flt_account_parent_pub =None #exists both in users_table
    flt_account_parent_idx= None

    ##generate a new random index key which is not present in the
    ## create_asset_idxs
    key_index = await ledger_utils.generate_key_index(
                                    array=create_asset_idxs)

    logging.info(f"User key index create_asset_idxs for user {key_index}")
    ##retrieve pub/priv key pair corresponding to the random index just
    ##generated
    nth_keys = await remote_calls.key_index_keys(app, decrypted_mnemonic,
                                                        [key_index])

    nth_priv, nth_pub = nth_keys[str(key_index)]["private_key"], \
                        nth_keys[str(key_index)]["public_key"]

    ## all the data being encrypted with user nth public key
    key, encrypted_key, s3_url, encrypted_s3_url = \
            await asset_utils.encrypt_file_data(requester["user_id"], nth_pub, app.config,
            file_data)


    master_key, master_url = await asset_utils.master_url_n_key(app.config.ADMIN_ZERO_PUB,
                                key, s3_url)

    ##the transaction will be signed by users nth private key
    create_asset_signer = ledger_utils.create_signer(nth_priv)

    ##we havent included the child_nth_pub in this transaction because it
    ## can be calculated from txn_key on the processor side



    asset_address = addresser.create_asset_address(
                        asset_id=nth_pub,
                        index=key_index)

    transaction_data= {"config": app.config,
                    "txn_key":create_asset_signer, "batch_key": app.config.SIGNER,
                    "key": encrypted_key,
                    "url": encrypted_s3_url,
                    "time": int(time.time()),
                    "indiantime": upload_utils.indian_time_stamp(),
                    "file_name": file_data["file_name"],
                    "file_hash":file_data["file_hash"],
                    "idx": key_index,
                    "master_key": master_key,
                    "master_url": master_url,
                    "role": requester["role"],
                    "scope": file_data["scope"],
                    "zero_pub": zero_pub,
                    "is_acc_claimed": True,
                    "flt_account_parent_pub": None,
                    "flt_account_parent_idx": None,
                    "child_zero_pub":  child_zero_pub,
                    }

    logging.info(f"THis is the transaction data {transaction_data}")
    transaction_ids, batch_id = await send_create_asset(**transaction_data)


    if batch_id:
        logging.info("Create Transaction has been created successfully")
        ##which imlies the transaction has been submitted successfully,
        ##now all the changes that are required to be done on the databse can
        ##be done
        ##Update users create_asset_idxs key on users entry will be updated by
        ## whomever will call this, because update can happend on pending_users
        ## table or users table depending upon user has been claimed or not.

        ##if transaction was submitted successfully
        ##Update user entry in the pending_users table of uer_table with the new
        ##new asset_index in creat_asset_idxs

        ##insert in asests with new asset created
        [transaction_data.pop(field) for field in ["config", "txn_key",
                                "batch_key", "is_acc_claimed", "flt_account_parent_pub",
                                "flt_account_parent_idx"]]
        transaction_data.update({
                    "user_id": requester["user_id"],
                    "public": nth_pub,
                    "transaction_id": transaction_ids[0],
                    "batch_id": batch_id,
                    "asset_address": asset_address,
                    "child_zero_pub": child_zero_pub

            })
        ##updating assets table with this new asset
        await assets_query.store_assets(app, transaction_data)

        ##updating org_state user_id in users table with new index of asset
        await accounts_query.update_create_asst_idxs(app,
                org_state["user_id"], key_index)


        if child_user_id:
            ##updating child_user_id user_id in users table with new index of asset
            await accounts_query.update_create_asst_idxs(app,
                child_user_id, key_index)

            #await accounts_query.update_create_asst_idxs_pending(app,
            #requester["user_id"], key_index)


        return nth_priv, nth_pub, key_index, asset_address
    else:
        logging.error("Create asset Faied, GO to hell Dude!!!!,\
         Kabhi kabhi lagta hai ki bhagwan hone ka bhi kya fayda")
    return
