




import time
from db import accounts_query
import hashlib
import upload.utils as upload_utils
#from encryption import utils as encryption_utils
#from addressing import addresser
#from encryption import asymmetric
#from encryption import symmetric
import ledger.utils as ledger_utils
from remotecalls import remote_calls
from ledger import deserialize_state
import random
from .send_child_account import send_child_account
from addressing import addresser
from encryption import signatures

import coloredlogs, logging
coloredlogs.install()

async def submit_child_account(app, parent_org, child):
    """
    Decrypt parent_org menmonic with the ADMIN private key
    Get orgnization account for parent_org
    Generate a random index at the child_account_idxs array of the
    Get Public/Private key pair at random_indexfrom parent_org mnemonic
    Generate child_address from this pair and index

    Signed nonce with zeroth public key of the parent_org
    """

    decrypted_mnemonic = await ledger_utils.decrypted_user_mnemonic(app,
                        parent_org["encrypted_admin_mnemonic"],
                        parent_org["role"])

    logging.info(decrypted_mnemonic)

    org_address = addresser.create_organization_account_address(
                parent_org["acc_zero_pub"], 0)

    org_account = await deserialize_state.deserialize_org_account(
                app.config.REST_API_URL, org_address)

    logging.info(org_account)
    ##lets chaeck if the parent user_i

    child_account_idxs = org_account.get("child_account_idxs")


    ##This will generate a new key which doesnt exists in the flt_acc_idxs array
    key_index = await ledger_utils.generate_key_index(child_account_idxs)
    logging.info(f"THis is the key index for parent {key_index}")

    nth_keys = await remote_calls.key_index_keys(app,
                                        decrypted_mnemonic, [key_index, 0])


    org_nth_priv, org_nth_pub = nth_keys[str(key_index)]["private_key"], \
                            nth_keys[str(key_index)]["public_key"]


    ##getting zeroth private key to be used later

    org_zeroth_priv, org_zeroth_pub = nth_keys[str(0)]["private_key"], \
                            nth_keys[str(0)]["public_key"]



    ##signer created from the parent key
    signer=upload_utils.create_signer(org_nth_priv)

    ##sending signatures, A nonce signed by zeroth_private_key
    nonce = random.randint(2**20, 2**31)
    nonce_hash = hashlib.sha224(str(nonce).encode()).hexdigest()
    hex_signatures = signatures.ecdsa_signature(org_zeroth_priv, nonce)


    ##import from ledger.account import float_account, other then create_asset_idxs
    ## wil be emprty for the float_account, if we push empty list on blockchain
    ##it wil hsow an error, its better to not to send them at the first place
    transaction_data= {"config": app.config,
                        "txn_key": signer,
                        "batch_key": app.config.SIGNER,

                        "parent_idx": key_index,
                        "parent_zero_pub": org_zeroth_pub,
                        "parent_role": parent_org["role"],

                        "first_name": child["first_name"],
                        "last_name": child["last_name"],
                        "org_name": child["org_name"],
                        "user_id": child["user_id"],
                        "pancard": child["pancard"],
                        "gst_number": child["gst_number"],
                        "tan_number": child["tan_number"],
                        "phone_number": child["phone_number"],
                        "email": child["email"],
                        "time": int(time.time()),
                        "indian_time": upload_utils.indian_time_stamp(),
                        "role": "CHILD",

                        "deactivate": False,
                        "deactivate_on": None,

                        "nonce": nonce,
                        "nonce_hash": nonce_hash,
                        "signed_nonce": hex_signatures
                        }



    transaction_ids, batch_id = await send_child_account(**transaction_data)

    logging.info(batch_id)
    if batch_id:
        ##if successful, insert this user in pending_users table
        child.update({"parent_idx": key_index,
                    "public": org_nth_pub,
                    "transaction_id": transaction_ids[0],
                    "batch_id": batch_id,
                    "parent_zero_pub": org_zeroth_pub,
                    "parent_role": parent_org["role"],
                    "nonce": nonce,
                    "nonce_hash": nonce_hash,
                    "signed_nonce": hex_signatures.decode(),
                    "time": transaction_data["time"],
                    "indian_time": transaction_data["indian_time"],
                    "role": "CHILD",
                    "deactivate": False,
                    "deactivate_on": None,

                    })

        logging.debug(child)
        await accounts_query.insert_account(app, child)

        ##update child_account_idxs array of the parent_org
        await accounts_query.update_child_account_idxs(app, parent_org["user_id"], key_index)



    return child
