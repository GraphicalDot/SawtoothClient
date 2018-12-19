




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
from encryption.utils import create_signer
from encryption.asymmetric import pub_encrypt

import coloredlogs, logging
import binascii
coloredlogs.install()




async def submit_share_mnemonic(app, requester_address, account,
                secret_share, index, private_key):


    acc_signer=create_signer(private_key)


    ##encrypting the shared mnemonic with users account public key
    ##the return will also be in bytes i.e encrypted_secret_share
    encrypted_secret_share = pub_encrypt(secret_share, account["public"])

    logging.info(encrypted_secret_share)
    secret_share = binascii.hexlify(encrypted_secret_share)

    transaction_data= {"config": app.config,
                        "txn_key": acc_signer,
                        "batch_key": app.config.SIGNER,
                        "ownership": account["address"],
                        "active": False,
                        "secret": secret_share,
                        "secret_hash": hashlib.sha512(secret_share).hexdigest(),
                        "requester_address": requester_address,
                        }



    transaction_ids, batch_id = await __send_share_mnemonic(**transaction_data)

    logging.info(batch_id)
    if batch_id:
        ##if successful, insert this user in pending_users table
        data = {"batch_key": app.config.SIGNER,
            "ownership": account_address,
            "active": False,
            "secret": secret_share,
            "user_account_address": requester_address,
            "index": index}


        #logging.debug(user_account)
        #await accounts_query.insert_account(app, user_account)

        ##update user pending_user with claim, claim_by , claimed_on keys
    return
