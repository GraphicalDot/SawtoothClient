




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
from .send_user_account import __send_user_account
from addressing import addresser
from routes import route_utils
from encryption.utils import create_signer
import coloredlogs, logging
coloredlogs.install()




async def submit_user_account(app, pancard=None, phone_number=None, email=None, role=None, \
                     password=None, first_name=None, last_name=None):
    """
    org_name is by default None for the user
    """
    if role != "USER":
        raise errors.CustomError("Roel required is USER")

    user = await route_utils.new_user_account(app, pancard=pancard, phone_number=phone_number,
                email=email, role=role, first_name=first_name, last_name=last_name)
    ##no9w the create account address and signer will be the user himself

    user_mnemonic, user_account = await route_utils.set_password(app, account=user, password=password)


    master_pub, master_priv, zero_pub, zero_priv = await \
                remote_calls.from_mnemonic(app.config.GOAPI_URL, user_mnemonic)


    acc_signer=create_signer(zero_priv)
    ##hashing gst number and tan number if present

    ##import from ledger.account import float_account, other then create_asset_idxs
    ## wil be emprty for the float_account, if we push empty list on blockchain
    ##it wil hsow an error, its better to not to send them at the first place
    find_hash = lambda x: hashlib.sha512(x.encode()).hexdigest() if x else None

    transaction_data= {"config": app.config,
                        "txn_key": acc_signer,
                        "batch_key": app.config.SIGNER,
                        "first_name": first_name,
                        "last_name": last_name,
                        "user_id": user_account["user_id"],
                        "pancard": find_hash(pancard),
                        "phone_number": find_hash(phone_number),

                        "email": find_hash(email),
                        "time": int(time.time()),
                        "indian_time": route_utils.indian_time_stamp(),
                        "role": "USER",
                        "deactivate": False,
                        "deactivate_on": None,
                        }



    transaction_ids, batch_id = await __send_user_account(**transaction_data)

    logging.info(batch_id)
    if batch_id:
        ##if successful, insert this user in pending_users table
        user_account.update({
                    "time": transaction_data["time"],
                    "indian_time": transaction_data["indian_time"],
                    "transaction_id": transaction_ids[0],
                    "batch_id": batch_id,
                    "role": "USER",
                    "pancard": transaction_data["pancard"],
                    })

        logging.debug(user_account)
        await accounts_query.insert_account(app, user_account)

        ##update user pending_user with claim, claim_by , claimed_on keys
    return user_account
