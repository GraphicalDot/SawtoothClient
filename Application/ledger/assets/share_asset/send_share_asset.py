
from ledger import messaging
import coloredlogs, logging
from errors.errors import ApiBadRequest, ApiInternalError
coloredlogs.install()
from pprint import pprint
import json
from addressing import addresser
from protocompiled import payload_pb2
from transactions.common import make_header_and_batch


async def send_share_asset(**in_data):


    inputs = [in_data["original_asset_address"],
            addresser.share_asset_address(
                in_data["txn_key"].get_public_key().as_hex(),
                in_data["idx"]),
            in_data["issuer_account_address"] #issuer_account_address
    ]

    outputs = [in_data["original_asset_address"],
            addresser.share_asset_address(
                in_data["txn_key"].get_public_key().as_hex(),
                in_data["idx"]),
            in_data["issuer_account_address"] #issuer_account_address

    ]

    if in_data["child_zero_pub"]:
        child_account_address = addresser.child_account_address(
                    in_data["child_zero_pub"], 0)
        inputs.append(child_account_address)
        outputs.append(child_account_address)


    share_asset = payload_pb2.CreateShareAsset(
            key=in_data["key"],
            url=in_data["url"],
            master_key=in_data["master_key"],
            master_url=in_data["master_url"],
            time=in_data["time"],
            indiantime=in_data["indiantime"],
            file_name=in_data["file_name"],
            file_hash=in_data["file_hash"],
            original_asset_address=in_data["original_asset_address"],
            revoked_on=in_data["revoked_on"],
            #details=in_data["details"],
            idx=in_data["idx"],
            account_signature=in_data["account_signature"],
            asset_signature=in_data["asset_signature"],
            nonce=in_data["nonce"],
            nonce_hash=in_data["nonce_hash"],
            to_org_name=in_data["to_org_name"],
            to_org_address=in_data["to_org_address"],
            issuer_account_address=in_data["issuer_account_address"],
            receive_asset_address = in_data["receive_asset_address"],
            child_zero_pub=in_data["child_zero_pub"],
            unique_code_hash=in_data["unique_code_hash"],

    )
    logging.info(pprint(share_asset))

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.SHARE_ASSET,
        share_asset=share_asset)

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
        logging.error(f"Transaction failed with {err}")
        raise ApiInternalError(err)
        #raise err
    return transaction_ids, batch_id
