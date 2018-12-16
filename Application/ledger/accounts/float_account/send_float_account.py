

from ledger import messaging
import coloredlogs, logging
from errors.errors import ApiBadRequest, ApiInternalError
coloredlogs.install()
from addressing import addresser
from protocompiled import payload_pb2
from transactions.common import make_header_and_batch

async def send_float_account(**in_data):
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
    inputs = [addresser.create_organization_account_address(
                        account_id=in_data["parent_zero_pub"],
                        index=0),
            addresser.float_account_address(
                        account_id=in_data["txn_key"].get_public_key().as_hex(),
                        index=in_data["parent_idx"]
         )
        ]

    logging.info(f"THe account address for the parent on blockchain {inputs[0]}")
    logging.info(f"THe float account address for the user {inputs[1]}")
    outputs = [addresser.create_organization_account_address(
                            account_id=in_data["parent_zero_pub"],
                            index=0),
                addresser.float_account_address(
                            account_id=in_data["txn_key"].get_public_key().as_hex(),
                            index=in_data["parent_idx"]
             )
            ]


    if in_data["child_zero_pub"]:

        child_address = addresser.child_account_address(
                    account_id=in_data["child_zero_pub"],
                    index=0
        )
        logging.info(f"CHILD address is {child_address}")
        inputs.append(child_address)
        outputs.append(child_address)


    logging.info(f"INPUTS ADDRESSES --<{inputs}>--")
    logging.info(f"OUTPUTS ADDRESSES --<{outputs}>--")


    float_account = payload_pb2.CreateFloatAccount(
              claimed_on=in_data["claimed_on"],
              org_name=in_data["org_name"],
              pancard=in_data["pancard"],
              gst_number=in_data["gst_number"],
              tan_number=in_data["tan_number"],
              phone_number=in_data["phone_number"],
              email=in_data["email"],
              claimed=in_data["claimed"],
              claimed_by=in_data["claimed_by"],
              create_asset_idxs=in_data["create_asset_idxs"],
              parent_idx=in_data["parent_idx"],
              time=in_data["time"],
              indian_time=in_data["indian_time"],
              parent_role=in_data["parent_role"],
              role=in_data["role"],
              parent_zero_pub=in_data["parent_zero_pub"],
              nonce=in_data["nonce"],
              nonce_hash=in_data["nonce_hash"],
              signed_nonce=in_data["signed_nonce"],
              child_zero_pub=in_data["child_zero_pub"]
    )

    logging.info(float_account)
    logging.info(f"THe serialized protobuf for float_account is {float_account}")

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.CREATE_FLOAT_ACCOUNT,
        create_float_account=float_account)

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
