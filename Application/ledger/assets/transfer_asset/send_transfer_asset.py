
from ledger import messaging
import coloredlogs, logging
from errors.errors import ApiBadRequest, ApiInternalError
coloredlogs.install()
from addressing import addresser
from protocompiled import payload_pb2
from transactions.common import make_header_and_batch


async def send_transfer_asset(**in_data):
    inputs = [in_data["receiver_address"], in_data["issuer_address"]]
    outputs = [in_data["receiver_address"], in_data["issuer_address"]]


    transfer_asset = payload_pb2.CreateTransferAsset(
            key=in_data["key"],
            url=in_data["url"],
            time=in_data["time"],
            indiantime=in_data["indiantime"],
            file_name=in_data["file_name"],
            file_hash=in_data["file_hash"],
            master_key=in_data["master_key"],
            master_url=in_data["master_url"],
            expired_on=in_data["expired_on"],
            scope=in_data["scope"],
            receiver_address=in_data["receiver_address"],
            issuer_address=in_data["issuer_address"],
            issuer_pub=in_data["issuer_pub"],
            issuer_zero_pub=in_data["issuer_zero_pub"],
            signed_nonce=in_data["signed_nonce"],
            nonce=in_data["nonce"],
            issuer_child_zero_pub=in_data["issuer_child_zero_pub"],

    )

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.TRANSFER_ASSET,
        transfer_asset=transfer_asset)

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
        logging.error(f"Transaction Failed with error {err}")
        raise ApiInternalError(err)
    return transaction_ids, batch_id
