

from ledger import messaging
import coloredlogs, logging
from errors.errors import ApiBadRequest, ApiInternalError
coloredlogs.install()

from addressing import addresser
from protocompiled import payload_pb2
from transactions.common import make_header_and_batch

async def __send_execute_share_mnemonic(**in_data):
    """

    """


    inputs = [in_data["ownership"],
            in_data["shared_secret_address"] #issuer_account_address
    ]

    outputs = [in_data["ownership"],
            in_data["shared_secret_address"] #iss
    ]


    execution_contract = payload_pb2.CreateExecuteShareSecret(
            shared_secret_address=in_data["shared_secret_address"],
            secret=in_data["secret"],
            timestamp=in_data["timestamp"],
            nonce=in_data["nonce"],
            nonce_hash=in_data["nonce_hash"],
            signed_nonce=in_data["signed_nonce"],
    )


    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.EXECUTE_SECRET,
        execute_secret=execution_contract)

    transaction_ids, batches, batch_id, batch_list_bytes= make_header_and_batch(
        payload=payload,
        inputs=inputs,
        outputs=outputs,
        txn_key=in_data["txn_key"],
        batch_key=in_data["batch_key"])


    logging.info(f"This is the batch_id {batch_id}")
    logging.info(f"Payload for execute share secret {payload}")
    rest_api_response = await messaging.send(
        batch_list_bytes,
        in_data["config"])


    try:
        result = await  messaging.wait_for_status(batch_id, in_data["config"])
    except (ApiBadRequest, ApiInternalError) as err:
        #await auth_query.remove_auth_entry(request.app.config.DB_CONN, request.json.get('email'))
        logging.error(f"Transaction failed with {err}")
        raise ApiInternalError(err)
        #raise err
    return transaction_ids, batch_id
