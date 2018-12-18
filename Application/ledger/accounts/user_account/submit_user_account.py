




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
from errors import errors
from .send_create_organization_account import send_organization_account
from addressing import addresser
from routes import route_utils
import coloredlogs, logging
coloredlogs.install()



async def submit_user_account(app, pancard=None, phone_number=None, email=None, role=None, \
                    gst_number=None, tan_number=None, password=None):
    """
    org_name is by default None for the user
    """
    if role != "USER":
            raise errors.CustomError("Roel required is USER")

    user = await route_utils.new_account(app, pancard=pancard, phone_number=phone_number, email=email, role=role, \
                        gst_number=gst_number, tan_number=tan_number, org_name=None)
    ##no9w the create account address and signer will be the user himself

    user_mnemonic, user_account = await set_password(app, account=user, password=password)


    master_pub, master_priv, zero_pub, zero_priv = await \
                remote_calls.from_mnemonic(app.config.GOAPI_URL, user_mnemonic)


    acc_signer=upload_utils.create_signer(zero_priv)
    ##hashing gst number and tan number if present

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
                                    sha512(user["pancard"].encode())\
                                    .hexdigest(),
                        "gst_number": hashlib.\
                                    sha512(user["gst_number"].encode())\
                                    .hexdigest(),
                        "tan_number": hashlib.\
                                    sha512(user["tan_number"].encode())\
                                    .hexdigest(),
                        "phone_number": hashlib.\
                                    sha512(user["phone_number"].encode())\
                                    .hexdigest(),

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
