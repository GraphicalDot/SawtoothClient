

from ledger import messaging
import coloredlogs, logging
from errors.errors import ApiBadRequest, ApiInternalError
coloredlogs.install()

from addressing import addresser
from protocompiled import payload_pb2
from transactions.common import make_header_and_batch
async def __send_organization_account(**in_data):
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
    inputs = [addresser.organization_address(
                        public=in_data["txn_key"].get_public_key().as_hex(),
                        index=0),
                ]


    outputs = [addresser.organization_address(
                        public=in_data["txn_key"].get_public_key().as_hex(),
                        index=0),

        ]

    account = payload_pb2.CreateOrganizationAccount(
            role = in_data["role"],
            phone_number = in_data["phone_number"],
            pancard = in_data["pancard"],
            user_id=in_data["user_id"],
            email=in_data["email"],
            org_name=in_data["org_name"],
            gst_number=in_data["gst_number"],
            tan_number=in_data["tan_number"],
            time=in_data["time"],
            indian_time=in_data["indian_time"],
            deactivate=in_data["deactivate"],
            deactivate_on=in_data["deactivate_on"],
            create_asset_idxs=in_data["create_asset_idxs"],
            )

    logging.info(account)
    logging.info(f"THe address for the user on blockchain {inputs[0]}")

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.CREATE_ORGANIZATION_ACCOUNT,
        create_organization_account=account)

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
