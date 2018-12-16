
from ledger import messaging
import coloredlogs, logging
from errors.errors import ApiBadRequest, ApiInternalError
coloredlogs.install()
from addressing import addresser
from protocompiled import payload_pb2
from transactions.common import make_header_and_batch

async def send_create_asset(**in_data):
    """
    Args
        key(str), hex_encoded: encrypted AES key with user publickey present
                at random index
        url(str): s3 url encrypted with user public key
        time(str): when this asset was created
        indiantime(str): time in indian format
        file_name(str): file_name
        file_hash(str): sha3_512 hash of file content
        child_idx(int): random index
        parent_zero_pub(str): Parent zero public key of the parent
        master_key(str): encrypted s3 url, encrypted with aes key generated
                        with qci_public and user private key
        master_url(str): encrypted s3 url, encrypted with aes key
                        generated with private key of user and  public of QCI
        scope(Scope(defined in asset.proto)):
        string expired_on=13; //the date on which this certificate is intended
    """
    ##TODO: Processor side : Float this asset and make change to create_asset_idxs
    ## to either float_Account_Address or create_Account_Address depending upon
    ##whther the user has been claimed or not
    inputs = [addresser.create_asset_address(
                    asset_id=in_data["txn_key"].get_public_key().as_hex(),
                    index=in_data["idx"]),
            ]

    outputs = [addresser.create_asset_address(
                    asset_id=in_data["txn_key"].get_public_key().as_hex(),
                    index=in_data["idx"])
            ]



    ##ideally if account is claimed, we should have nothing to do with float account
    ## but we are sending both addresses to the processor and let processor handle
    ## the logic i.e float_account should exists and is_claimed shall be true
    ##to append create_asset_idxs to the account_transaction
    if not in_data["is_acc_claimed"]:
        ##implies user havent claimed his float_account_address, so the
        ## create_asset_idx aill be chnaged on flt_account_addresslogging.info("Float account parent pub %s"%in_data["flt_account_parent_pub"])
        logging.info("Float account parent idx %s"%str(in_data["flt_account_parent_idx"]))
        float_account_address = addresser.float_account_address(
                    account_id=in_data["flt_account_parent_pub"],
                    index=in_data["flt_account_parent_idx"])
        inputs.append(float_account_address)
        outputs.append(float_account_address)
    else:

        account_address = addresser.create_organization_account_address(
            account_id=in_data["zero_pub"],
            index=0
            )


        inputs.append(account_address)
        outputs.append(account_address)

    if in_data["child_zero_pub"]:
        child_address = addresser.child_account_address(
                    account_id=in_data["child_zero_pub"],
                    index=0
                    )
        inputs.append(child_address)
        outputs.append(child_address)

    if in_data["scope"]:
        scope = payload_pb2.PayloadScope(
            group=in_data["scope"]["group"],
            sub_group=in_data["scope"]["sub_group"],
            field=in_data["scope"]["field"],
            nature=in_data["scope"]["nature"],
            operations=in_data["scope"]["operations"],
            description=in_data["scope"]["description"],
            )
    else:
        scope=None

    logging.info(f"Input Address<<{inputs}>>")
    logging.info(f"Output Address<<{outputs}>>")

    asset = payload_pb2.CreateAsset(
            key=in_data["key"],
            url=in_data["url"],
            time=in_data["time"],
            indiantime=in_data["indiantime"],
            file_name=in_data["file_name"],
            file_hash=in_data["file_hash"],
            idx=in_data["idx"],
            master_key=in_data["master_key"],
            master_url=in_data["master_url"],
            role=in_data["role"],
            scope=scope,
            zero_pub=in_data["zero_pub"],
            flt_account_parent_pub=in_data["flt_account_parent_pub"],
            flt_account_parent_idx=in_data["flt_account_parent_idx"],
            child_zero_pub=in_data["child_zero_pub"]
    )

    logging.info(f"Create asset transaction {asset}")
    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.CREATE_ASSET,
        create_asset=asset)

    transaction_ids, batches, batch_id, batch_list_bytes =make_header_and_batch(
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
