

from ledger import messaging
import coloredlogs, logging
from errors.errors import ApiBadRequest, ApiInternalError
coloredlogs.install()
from addressing import addresser
from protocompiled import payload_pb2
from transactions.common import make_header_and_batch

async def send_child_account(**in_data):
    """
        txn_key(sawtooth_signing.Signer): signer created from user zeroth public key
        batch_key(sawtooth_signing.Signer):  signer created from QCI mnemonic zero private key,
        pancard(str): pancard of the user ,
        phone_number(str): phone_number of the user,
        email(str): email of the user,
        claimed(bool): If this float account is claimed or not,
        claimed_by(str): Public key of the user for whom this float_acc transaction,
        create_asset_index(int): random key index at which the first asset was created,
        parent_pub(str): public key of the parent ,
        parent_idx(str): Required to be appened to parent accoutn flt_key_inds, key_index,
        time=time.time();
        indian_time=indian_time_stamp(),
        claimed_on(str): Date on which this flt account was claimed and converted to create account)
    """
    inputs = [
            addresser.create_organization_account_address(
                        account_id=in_data["parent_zero_pub"],
                        index=0),
            addresser.child_account_address(
                account_id=in_data["txn_key"].get_public_key().as_hex(),
                index=0),
                ]


    outputs = [
        addresser.create_organization_account_address(
                    account_id=in_data["parent_zero_pub"],
                    index=0),
        addresser.child_account_address(
            account_id=in_data["txn_key"].get_public_key().as_hex(),
            index=0),
            ]

    account = payload_pb2.CreateChildAccount(
            parent_zero_pub=in_data["parent_zero_pub"],
            parent_idx=in_data["parent_idx"],
            parent_role=in_data["parent_role"],

            org_name=in_data["org_name"],
            first_name=in_data["first_name"],
            last_name=in_data["last_name"],

            user_id=in_data["user_id"],
            pancard = in_data["pancard"],
            gst_number=in_data["gst_number"],
            tan_number=in_data["tan_number"],
            phone_number = in_data["phone_number"],
            email=in_data["email"],

            time=in_data["time"],
            indian_time=in_data["indian_time"],
            role = in_data["role"],

            deactivate=in_data["deactivate"],
            deactivate_on=in_data["deactivate_on"],

            nonce=in_data["nonce"],
            nonce_hash=in_data["nonce_hash"],
            signed_nonce=in_data["signed_nonce"],

            )

    logging.info(account)
    logging.info(f"THe address for the user on blockchain {inputs[0]}")

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.CREATE_CHILD_ACCOUNT,
        create_child_account=account)

    logging.info(payload)
    transaction_ids, batches, batch_id, batch_list_bytes= make_header_and_batch(
        payload=payload,
        inputs=inputs,
        outputs=outputs,
        txn_key=in_data["txn_key"],
        batch_key=in_data["batch_key"])



    logging.info(f"This is the batch_id {batch_id}")

    rest_api_response = await messaging.send(
        batch_list_bytes,
        in_data["config"])


    try:
        result = await  messaging.wait_for_status(batch_id, in_data["config"])
    except (ApiBadRequest, ApiInternalError) as err:
        #await auth_query.remove_auth_entry(request.app.config.DB_CONN, request.json.get('email'))
        raise err
        return False, False

    return transaction_ids, batch_id
