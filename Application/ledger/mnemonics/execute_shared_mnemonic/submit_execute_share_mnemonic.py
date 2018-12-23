

import coloredlogs, logging
coloredlogs.install()
import binascii
import random
import hashlib
from encryption.utils import create_signer, decrypt_w_privkey
from routes.resolve_account import ResolveAccount
from remotecalls import remote_calls
from encryption.symmetric import aes_decrypt, aes_encrypt
from encryption.asymmetric import priv_decrypt
from encryption.signatures import ecdsa_signature
from routes.route_utils import indian_time_stamp
from .__send_execute_share_mnemonic import __send_execute_share_mnemonic

async def submit_execute_share_mnemonic(app, requester, shared_secret_state):

    logging.info(shared_secret_state)
    user = await ResolveAccount(requester, app)

    nth_keys = await remote_calls.key_index_keys(app,
                            user.decrypted_mnemonic, [0])

    requester_zero_priv = nth_keys[str(0)]["private_key"]
    requester_zero_pub = nth_keys[str(0)]["public_key"]


    secret = shared_secret_state["secret"] ##encrypted secret with AES key i.e key
    reset_key =shared_secret_state["reset_key"] ##new aes key which will be
                                    #used to encrypt the secret after decryption
    key = shared_secret_state["key"] #THE aes key which was oriniginally used to encrypt secret

    ##the key is hex encoed but this function will first dehelify it and then
    ## decrypt with private key
    de_org_key = decrypt_w_privkey(key, requester_zero_priv)

    #this orginal AES key de_org_key will be in bytes

    unhexlified_secret = binascii.unhexlify(secret)

    ##This is the bare secret which was originally shared with this user
    de_org_secret = aes_decrypt(de_org_key, unhexlified_secret)


    ##Now we have to decrypt the new aes key which user has updated as reset_key
    ##in this contract
    ##It was also encrypted with the public key of the account address

    de_reset_key = priv_decrypt(binascii.unhexlify(reset_key), requester_zero_priv)



    ##now encypting orginila share with new reset key
    ciphertext, tag, nonce = aes_encrypt(de_reset_key, de_org_secret)
    secret = b"".join([tag, ciphertext, nonce])


    ##encrypting the shared mnemonic with users account public key
    ##the return will also be in bytes i.e encrypted_secret_share
    #encrypted_secret_share = pub_encrypt(secret_share, account["public"])

    #logging.info(encrypted_secret_share)
    #secret_share = binascii.hexlify(encrypted_secret_share)

    nonce = random.randint(2**20, 2**30)
    ##nonce signed by zerothprivate key and in hex format
    signed_nonce = ecdsa_signature(requester_zero_priv, nonce)
    nonce_hash= hashlib.sha512(str(nonce).encode()).hexdigest()
    acc_signer=create_signer(requester_zero_priv)


    transaction_data= {"config": app.config,
                        "txn_key": acc_signer,
                        "batch_key": app.config.SIGNER,
                        "shared_secret_address": shared_secret_state["address"],
                        "secret": binascii.hexlify(secret),
                        "timestamp": indian_time_stamp(),
                        "ownership": shared_secret_state["ownership"],
                        "nonce": nonce,
                        "nonce_hash": nonce_hash,
                        "signed_nonce": signed_nonce,
                        }

    transaction_ids, batch_id = await __send_execute_share_mnemonic(**transaction_data)

    if transaction_ids:
        """
        logging.info("Execute share secret Transaction has been created successfully")
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
        """
    else:
        return False
    return
