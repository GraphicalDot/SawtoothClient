
import time
import hashlib
import random
from db import accounts_query
import upload.utils as upload_utils
from encryption import utils as encryption_utils
from addressing import addresser
from encryption import asymmetric
from encryption import symmetric
from encryption import signatures

import ledger.utils as ledger_utils
from ledger import deserialize_state
from remotecalls import remote_calls
from .send_float_account import send_float_account

import coloredlogs, logging
coloredlogs.install()


async def submit_float_account(app, requester, user):

    ##retrive float_account from parent

    ## handle if the parent is actually a child account, then the flt_acc_idxs
    ## of the parent must be used

    ##elseif organization is directly creating another org account then its
    ## own flt_account_idxs must be used

    ##a junk entry needs to be sent which is A once signed by the parent orgnisation of the
    ## child or the organization itself zeroth_private_key, which that the float_account is
    ## actually being sent by the concerned authority, otherwise anyone can generate any
    ## random keys and then make a float_transaction because we are not checking any other details
    ## for cros checking


    if requester["role"] == "CHILD":
        ##now find the parent pub of this child to track the parent
        ##organization account
        ##child will get the flt_acc_idxs of the parent organization
        org_address = addresser.create_organization_account_address(
                    requester["parent_zero_pub"], 0)

        org_account = await deserialize_state.deserialize_org_account(
                    app.config.REST_API_URL, org_address)

        logging.info(org_account)
        ##lets chaeck if the parent user_id hash matched with the child parent_id
        if requester["parent_idx"] not in org_account["child_account_idxs"]:
            raise Exception("Child parent_idx not in parent org child_account_idxs")


        if requester["org_name"] != org_account["org_name"]:
            raise Exception("Child org_name is different from  parent")


        ##since child was created from the PUblic key present at parent_idx at the
        ##parent org mnemonic, We need to get that so that we can generated child
        ##adddress, Remember, child_account_addresses generates from parent_org
        ##not with the zeroth key of the child mnemonic

        ##TODO: you can also check whether the child address generated from
        #parent org public key pair at requester parent_idx is same as requester
        ## address
        ##float_account_idxs array of the child's parent organisation

        flt_acc_idxs = org_account.get("float_account_idxs")

        ##now we need to decrypt the parent mnemonic so that we can get the Public/private key
        ##pair corresponding to the the random index
        parent_id = org_account["user_id"]
        logging.info(f"Parent id for the child is {parent_id} and\
            float_account_idxs are {flt_acc_idxs}")

        org_db = await accounts_query.find_on_key(app, "user_id", parent_id)

        logging.info(org_db)
        if org_db["role"] != "ADMIN":
            decrypted_mnemonic = await ledger_utils.decrypted_user_mnemonic(
                                app,
                                org_db["encrypted_admin_mnemonic"],
                                org_db["role"])
        else:
            decrypted_mnemonic = app.config.ADMIN_MNEMONIC
        logging.info(decrypted_mnemonic)


        nth_keys = await remote_calls.key_index_keys(app,
                                decrypted_mnemonic, [requester["parent_idx"]])


        nth_priv, nth_pub = nth_keys[str(requester["parent_idx"])]["private_key"], \
                            nth_keys[str(requester["parent_idx"])]["public_key"]


        zero_pub = org_db["acc_zero_pub"]
        parent_role = org_db["role"]
        child_zero_pub = nth_pub

    else: #orgnisation itself is creating this float_account
        logging.info(requester)

        ##float_account_idxs array of the orgnization itself
        flt_acc_idxs = await accounts_query.get_field(app, requester["user_id"],
                "float_account_idxs")
        flt_acc_idxs = flt_acc_idxs.get("float_account_idxs")

        logging.info(f"Float account indxs for the orgnization {flt_acc_idxs}")
        decrypted_mnemonic = await ledger_utils.decrypted_user_mnemonic(app,
                                requester["encrypted_admin_mnemonic"],
                                requester["role"])

        logging.info(decrypted_mnemonic)

        zero_pub = requester["acc_zero_pub"]
        parent_role = requester["role"]
        child_zero_pub = None


    logging.info(f"This is the decrypted mnemonic for parent {decrypted_mnemonic}")

    ##This will generate a new key which doesnt exists in the flt_acc_idxs array
    key_index = await ledger_utils.generate_key_index(flt_acc_idxs)
    logging.info(f"THis is the key index for parent {key_index}")

    nth_keys = await remote_calls.key_index_keys(app,
                                        decrypted_mnemonic, [key_index, 0])


    nth_priv, nth_pub = nth_keys[str(key_index)]["private_key"], \
                            nth_keys[str(key_index)]["public_key"]


    ##getting zeroth private key to be used later

    zeroth_priv, zeroth_pub = nth_keys[str(0)]["private_key"], \
                            nth_keys[str(0)]["public_key"]

    flt_acc_address = addresser.float_account_address(nth_pub,
                key_index)

    logging.info(f"This is the flt acc addressfor user {flt_acc_address}")
    logging.info(f"Checking if valid account address has been generated\
                                    {addresser.address_is(flt_acc_address)}")


    ##signer created from the parent key
    flt_acc_signer=upload_utils.create_signer(nth_priv)

    ##sending signatures, A nonce signed by zeroth_private_key
    nonce = random.randint(2**20, 2**31)
    nonce_hash = hashlib.sha224(str(nonce).encode()).hexdigest()
    hex_signatures = signatures.ecdsa_signature(zeroth_priv, nonce)


    ##hashing gst number and tan number if present
    if user.get("gst_number"):
        gst_number = hashlib.sha224(user["gst_number"].encode()).hexdigest()
    else:
        gst_number = None

    if user.get("tan_number"):
        tan_number = hashlib.sha224(user["tan_number"]\
                            .encode()).hexdigest()
    else:
        tan_number = None

    ##import from ledger.account import float_account
    transaction_data= {"config": app.config,
                        "txn_key": flt_acc_signer,
                        "batch_key": app.config.SIGNER,
                        "org_name": user["org_name"],
                        "pancard": hashlib.sha224(user["pancard"]\
                                            .encode()).hexdigest(),
                        "gst_number": gst_number,
                        "tan_number": tan_number,
                        "phone_number": user["phone_number"],
                        "email": user["email"],
                        "claimed": False,
                        "claimed_by": None,
                        "create_asset_idxs": [],
                        "parent_pub": nth_pub,
                        "parent_idx": key_index,
                        "time": int(time.time()),
                        "indian_time": upload_utils.indian_time_stamp(),
                        "parent_zero_pub": zero_pub,
                        "parent_role": parent_role,
                        "role": user["role"],
                        "claimed_on": None,
                        "nonce": nonce,
                        "nonce_hash": nonce_hash,
                        "signed_nonce": hex_signatures,
                        "child_zero_pub": child_zero_pub
                        }

    transaction_ids, batch_id = await send_float_account(**transaction_data)

    if batch_id:
        logging.debug(user)
        ##if successful, insert this user in pending_users table
        user.update({"parent_pub": nth_pub,
                    "parent_idx": key_index,
                    "time": transaction_data["time"],
                    "indian_time": transaction_data["indian_time"],
                    "parent_zero_pub": transaction_data["parent_zero_pub"],
                    "parent_role": transaction_data["parent_role"],
                    "transaction_id": transaction_ids[0],
                    "batch_id": batch_id,
                    "child_zero_pub": child_zero_pub,
                    })
        logging.debug(f"User after submitting float_Account trasaction {user}")
        await accounts_query.insert_pending_account(app, user)

    if requester["role"] == "CHILD":
        ##update parent create_flt_idcs array
        await accounts_query.update_flt_acc_idxs(app, org_db["user_id"], key_index)
        ##update float_account_idxs of the child also, so that we would
        ##know which child created which float_account_idxs
        await accounts_query.update_flt_acc_idxs(app, requester["user_id"], key_index)

    else:
        await accounts_query.update_flt_acc_idxs(app, requester["user_id"], key_index)

    ##return new user data whose float_account has just been created
    return user
