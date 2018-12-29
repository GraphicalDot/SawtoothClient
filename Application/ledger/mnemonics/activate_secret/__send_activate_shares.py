

from ledger import messaging
import coloredlogs, logging
from errors.errors import ApiBadRequest, ApiInternalError
coloredlogs.install()

from addressing import addresser
from protocompiled import payload_pb2
from transactions.extended_batch import make_header_and_batch

async def __send_activate_shares(**in_data):
    """

    """
    ##the requester will account will be updated with the public key of the
    ## shared_secret_address
    ##on the shared secret address, data will be appended
    inputs = [in_data["share_secret_address"], in_data["admin_address"]]

    outputs = [in_data["share_secret_address"], in_data["admin_address"]]


    payload = payload_pb2.CreateActivateSecret(
        share_secret_address = in_data["share_secret_address"],
        reset_key =in_data["reset_key"],
        nonce=in_data["nonce"],
        nonce_hash=in_data["nonce_hash"],
        signed_nonce=in_data["signed_nonce"],
        admin_address=in_data["admin_address"],
        timestamp=in_data["timestamp"]
            )

    logging.info(payload)

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.ACTIVATE_SECRET,
        activate_secret=payload)

    logging.info(payload)

    return make_header_and_batch(
        payload=payload,
        inputs=inputs,
        outputs=outputs,
        txn_key=in_data["txn_key"],
        batch_key=in_data["batch_key"])
