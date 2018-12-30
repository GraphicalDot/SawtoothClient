

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
from ledger.send_transaction import SendExecuteSecret
from protocompiled import payload_pb2

async def submit_execute_share_secret(app, requester, receive_secret_address,
                    shared_secret_state, private, public):
    """
    app(dict): configuration of the whole application
    requester(dict): database entry of the user who requested this api, i.e who tries to
            execute a share_Secret transactions shared with him on his receive_secret
            transaction
    share_secret_state(dict): Blcokchain state of the share_secret tansaction
        which will be executed by this user
    private(hex encoded string): Private key of the requester with whom the
        receive secret transaction was created, this private was generaed from the idx
        mentioned in the receive_secret transaction from the requester mnemonic

    public(hex encoded string): corresponding public of the private

    Process:
        share_secret transaction has three keys ,
            key: hex encoded AES key encrypted with the public key of the requester
            secret: hex encoded shamir secret share encrypted with the AES key
                    mentioned above
            reset_key: The new hex encoded key generated from the users new_password
                this is also encrypted with requester public key.

    Step1: decrypt hex encoded KEY (AES) with private key
    Step2: decrypt unhexlified secret with AES key from step1.
    Step3: decrypt unhexlified reset_key with private_key
    Step4: Encrypt Secret with reset_key
    """

    secret = shared_secret_state["secret"] ##encrypted secret with AES key i.e key
    reset_key =shared_secret_state["reset_key"] ##new aes key which will be
                                    #used to encrypt the secret after decryption
    key = shared_secret_state["key"] #THE aes key which was oriniginally used to encrypt secret

    ##the key is hex encoed but this function will first dehexlify it and then
    ## decrypt with private key
    de_org_key = decrypt_w_privkey(key, private)

    #this orginal AES key de_org_key will be in bytes

    unhexlified_secret = binascii.unhexlify(secret)

    ##This is the bare secret which was originally shared with this user
    de_org_secret = aes_decrypt(de_org_key, unhexlified_secret)


    ##Now we have to decrypt the new aes key which user has updated as reset_key
    ##in this contract
    ##It was also encrypted with the public key of the account address

    de_reset_key = priv_decrypt(binascii.unhexlify(reset_key), private)



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
    signed_nonce = ecdsa_signature(private, nonce)
    nonce_hash= hashlib.sha512(str(nonce).encode()).hexdigest()
    acc_signer=create_signer(private)


    transaction_data= {"shared_secret_address": shared_secret_state["address"],
                        "reset_secret": binascii.hexlify(secret),
                        "timestamp": indian_time_stamp(),
                        "nonce": nonce,
                        "nonce_hash": nonce_hash,
                        "signed_nonce": signed_nonce,
                        }


    addresses = [shared_secret_state["ownership"], receive_secret_address]
    logging.info(f"addresses are {addresses}")

    payload = payload_pb2.CreateExecuteShareSecret(**transaction_data)

    instance = await SendExecuteSecret(app.config.REST_API_URL, app.config.TIMEOUT)
    transaction_id, batch_id = await instance.push_receive_secret(
                            txn_key=acc_signer, batch_key=app.config.SIGNER,
                            inputs=addresses, outputs=addresses, payload=payload)


    logging.info(transaction_data)
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
