




import time
from db import accounts_query
import hashlib
import upload.utils as upload_utils
#from encryption import utils as encryption_utils
#from addressing import addresser
#from encryption import asymmetric
#from encryption import symmetric
#import ledger.utils as ledger_utils
from remotecalls import remote_calls
from ledger import deserialize_state

from .send_create_organization_account import send_organization_account
from addressing import addresser

import coloredlogs, logging
coloredlogs.install()





async def submit_admin_account(app, user):
    acc_signer= upload_utils.create_signer(app.config.ADMIN_ZERO_PRIV)

    transaction_data= {"config": app.config,
                        "txn_key": acc_signer,
                        "batch_key": app.config.SIGNER,
                        "org_name": user["org_name"],
                                                        #float_account address
                        "user_id": user["user_id"],
                        "pancard": hashlib.\
                                    sha3_224(app.config.ADMIN_PANCARD.encode())\
                                    .hexdigest(),
                        "gst_number": app.config.ADMIN_GST_NUMBER,
                        "tan_number": app.config.ADMIN_TAN_NUMBER,
                        "phone_number": user["phone_number"],
                        "email": user["email"],
                        "time": int(time.time()),
                        "indian_time": upload_utils.indian_time_stamp(),
                        "parent_zero_pub": None,
                        "parent_role": None,
                        "role": user["role"],
                        "create_asset_idxs": [],
                        "deactivate": False,
                        "deactivate_on": None,
                        "parent_pub": None,
                        "parent_idx": None,
                        "float_account_address": None,
                        }



    transaction_ids, batch_id = await send_organization_account(**transaction_data)

    logging.info(batch_id)
    if batch_id:

        user.update({
                "transaction_id": transaction_ids[0],
                "batch_id": batch_id,
                "time": transaction_data["time"],
                "indian_time": transaction_data["indian_time"],
        })
        result  = await accounts_query.insert_account(app, user)
        logging.info(result)
        return True
    return

async def submit_organization_account(app, user):
    """
    """

    ##no9w the create account address and signer will be the user himself

    master_pub, master_priv, zero_pub, zero_priv = await \
                remote_calls.from_mnemonic(app.config.GOAPI_URL, user["mnemonic"])

    if user["acc_zero_pub"] != zero_pub:
        raise Exception("wrong mnemonic for user, Key mismatch error")
    acc_signer=upload_utils.create_signer(zero_priv)
    ##hashing gst number and tan number if present

    ##fecth float account details from the blokchchain, because it might be a possibility
    ##that there are several create_asset transaction in pipeline, and the user
    ## now start the procedute to claim the acccount, Now if we fetch pending user
    ## rom db rather then blokchcain then flt_acc_idxs will differ

    flt_acc_address = addresser.float_account_address(
                user["parent_pub"], user["parent_idx"])

    flt_account = await deserialize_state.deserialize_float_account(
                app.config.REST_API_URL, flt_acc_address)



    ##import from ledger.account import float_account, other then create_asset_idxs
    ## wil be emprty for the float_account, if we push empty list on blockchain
    ##it wil hsow an error, its better to not to send them at the first place
    transaction_data= {"config": app.config,
                        "txn_key": acc_signer,
                        "batch_key": app.config.SIGNER,
                        "org_name": user["org_name"],
                        "parent_pub": user["parent_pub"], #required to find
                                                        #float_account address
                        "user_id": user["user_id"],
                        "pancard": hashlib.\
                                    sha224(user["pancard"].encode())\
                                    .hexdigest(),
                        "gst_number": user["gst_number"],
                        "tan_number": user["tan_number"],
                        "phone_number": user["phone_number"],
                        "email": user["email"],
                        "time": int(time.time()),
                        "indian_time": upload_utils.indian_time_stamp(),
                        "parent_zero_pub": user["parent_zero_pub"],
                        "parent_role": user["parent_role"],
                        "role": user["role"],
                        "create_asset_idxs": flt_account.get("create_asset_idxs"),
                        "deactivate": False,
                        "deactivate_on": None,
                        "parent_idx": user["parent_idx"],
                        "float_account_address": flt_acc_address,
                        }



    transaction_ids, batch_id = await send_organization_account(**transaction_data)

    logging.info(batch_id)
    if batch_id:
        logging.debug(user)
        ##if successful, insert this user in pending_users table
        user.update({
                    "time": transaction_data["time"],
                    "indian_time": transaction_data["indian_time"],
                    "transaction_id": transaction_ids[0],
                    "batch_id": batch_id,
                    "create_asset_idxs": flt_account.get("create_asset_idxs"),
                    "type": "ORGANIZATION"})

        user.pop("mnemonic")
        logging.debug(user)
        await accounts_query.insert_account(app, user)

        ##update user pending_user with claim, claim_by , claimed_on keys
        await accounts_query.claim_account(app, user["user_id"],
                user["email"], user["phone_number"], user["indian_time"])
    ##return new user data whose float_account has just been created
    return user
