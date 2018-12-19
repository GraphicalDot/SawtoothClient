

from ledger import messaging
import coloredlogs, logging
from errors.errors import ApiBadRequest, ApiInternalError
coloredlogs.install()

from addressing import addresser
from protocompiled import payload_pb2
from transactions.common import make_header_and_batch
async def __send_user_account(**in_data):
    """

    """
    inputs = [addresser.user_address(
                        public=in_data["txn_key"].get_public_key().as_hex(),
                        index=0),
                ]


    outputs =  [addresser.user_address(
                            public=in_data["txn_key"].get_public_key().as_hex(),
                            index=0),
                    ]


    account = payload_pb2.CreateUserAccount(
            role = in_data["role"],
            phone_number = in_data["phone_number"],
            pancard = in_data["pancard"],
            first_name = in_data["first_name"],
            last_name = in_data["last_name"],
            user_id=in_data["user_id"],
            email=in_data["email"],
            time=in_data["time"],
            indian_time=in_data["indian_time"],
            deactivate=in_data["deactivate"],
            deactivate_on=in_data["deactivate_on"],
            )

    logging.info(account)
    logging.info(f"THe address for the user on blockchain {inputs[0]}")

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.CREATE_USER_ACCOUNT,
        create_user_account=account)

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
