
from ledger import messaging
import coloredlogs, logging
from errors.errors import ApiBadRequest, ApiInternalError
coloredlogs.install()
from addressing import addresser
from protocompiled import payload_pb2
from transactions.common import make_header_and_batch


async def send_receive_asset(**in_data):
    """
    """
    address = addresser.receive_asset_address(
                asset_id=in_data["txn_key"].get_public_key().as_hex(),
                index=in_data["idx"])

    inputs = [in_data["org_address"], address]
    outputs=[in_data["org_address"], address]
    logging.info(in_data)
    if in_data["child_zero_pub"]:

        child_address = addresser.child_account_address(
                    account_id=in_data["child_zero_pub"],
                    index=0
        )
        logging.info(f"CHILD address is {child_address}")
        inputs.append(child_address)
        outputs.append(child_address)

    if in_data["receive_asset_details"]:
        receive_asset_details = payload_pb2.ReceiveAssetDetails(
            name=in_data["receive_asset_details"]["name"],
            description=in_data["receive_asset_details"]["description"],
            )
    receive_asset = payload_pb2.CreateReceiveAsset(
            _id_=in_data["_id_"],
            time=in_data["time"],
            indiantime=in_data["indiantime"],
            idx=in_data["idx"],
            at_which_asset_expires=in_data["at_which_asset_expires"],
            org_name=in_data["org_name"],
            org_address=in_data["org_address"],
            org_role=in_data["org_role"],
            org_zero_pub=in_data["org_zero_pub"],
            receive_asset_details=receive_asset_details,
            child_zero_pub=in_data["child_zero_pub"],
            signed_nonce=in_data["signed_nonce"],
            nonce=in_data["nonce"],
            nonce_hash=in_data["nonce_hash"],
            unique_code_hash=in_data["unique_code_hash"],
            encrypted_unique_code=in_data["encrypted_unique_code"],
            encrypted_admin_unique_code=in_data["encrypted_admin_unique_code"]
    )

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.RECEIVE_ASSET,
        receive_asset=receive_asset)
    logging.info(payload)
    transaction_ids, batches, batch_id, batch_list_bytes = make_header_and_batch(
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
        logging.error(f"Transaction failed with {err}")
        raise ApiInternalError(err)
        #raise err
    return transaction_ids, batch_id
