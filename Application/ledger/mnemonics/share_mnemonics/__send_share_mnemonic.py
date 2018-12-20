

from ledger import messaging
import coloredlogs, logging
from errors.errors import ApiBadRequest, ApiInternalError
coloredlogs.install()

from addressing import addresser
from protocompiled import payload_pb2
from transactions.extended_batch import make_header_and_batch

async def __send_share_mnemonic(**in_data):
    """

    """
    ##the requester will account will be updated with the public key of the
    ## shared_secret_address
    ##on the shared secret address, data will be appended
    inputs = [in_data["requester_address"],
                addresser.shared_secret_address(
                    in_data["txn_key"].get_public_key().as_hex(), in_data["idx"])
                ]

    outputs = [in_data["requester_address"],
            addresser.shared_secret_address(
                in_data["txn_key"].get_public_key().as_hex(), in_data["idx"])

                ]


    logging.info(inputs)
    payload = payload_pb2.CreateShareSecret(
            secret = in_data["secret"],
            active = in_data["active"],
            ownership = in_data["ownership"],
            secret_hash=in_data["secret_hash"],
            key=in_data["key"],
            role=in_data["role"],
            idx=in_data["idx"],
            user_address= in_data["requester_address"] #the user address who is sharing the mnemonic
            )

    logging.info(payload)

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.SHARE_SECRET,
        share_secret=payload)

    logging.info(payload)

    return make_header_and_batch(
        payload=payload,
        inputs=inputs,
        outputs=outputs,
        txn_key=in_data["txn_key"],
        batch_key=in_data["batch_key"])
