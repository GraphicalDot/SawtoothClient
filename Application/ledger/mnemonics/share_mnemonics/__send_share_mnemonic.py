

from ledger import messaging
import coloredlogs, logging
from errors.errors import ApiBadRequest, ApiInternalError
coloredlogs.install()

from addressing import addresser
from protocompiled import payload_pb2
from transactions.common import make_header_and_batch

async def __send_share_mnemonic(**in_data):
    """

    """
    ##the requester will account will be updated with the public key of the
    ## shared_secret_address
    ##on the shared secret address, data will be appended
    inputs = [in_data["requester_address"],
                in_data["txn_key"].get_public_key().as_hex()
                ]

    outputs = [in_data["requester_address"],
                in_data["txn_key"].get_public_key().as_hex()
                ]



    payload = payload_pb2.CreateShareSecret(
            secret = in_data["secret"],
            active = in_data["active"],
            ownership = in_data["ownership"],
            secret_hash=in_data["secret_hash"],
            )

    logging.info(payload)

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.SHARE_SECRET,
        share_secret=payload)

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
