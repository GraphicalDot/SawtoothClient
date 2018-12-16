
import rethinkdb as r
from rethinkdb.errors import ReqlNonExistenceError
from errors.errors import ApiBadRequest, AccountCreationError, \
            AssetCreationError, DBError
from db.accounts_query import find_user_field, find_on_key, cursor_to_result



import coloredlogs, logging
coloredlogs.install()


async def find_receive_asset(app, public, idx):
    """
    Public is the zeroth public key of the account and the idx is the
    random idx generated in receive_asset?_idxs of the account present
    at the address generated at zeroth_index and account_id is public

    """
    try:
        cursor = await r.table(app.config.DATABASE["receive_asset"])\
            .filter({"org_zero_pub": public, "idx": idx})\
            .run(app.config.DB)
    except Exception as e:
        logging.info(f"receive asset find failed with error --<{e}>--")
        raise DBError(f"Database Error{e}")

    return await cursor_to_result(cursor)




async def store_receive_assets(app, data):
    if await find_receive_asset(app, data["org_zero_pub"], data["idx"]):
        logging.error("This transfer_asset transaction is already present in\
                the database")
        raise Exception("This transfer_asset transaction is already present in\
                the database")

    try:
        return await r.table(app.config.DATABASE["receive_asset"])\
            .insert(data).run(app.config.DB)
    except ReqlNonExistenceError as e:
        logging.error(f"Error in inserting {data} which is {e}")
        raise ApiBadRequest(
            f"Error in storing receive asset {e}")

    return



async def receive_asset_unique_code(app, receive_asset_state):

    try:
         cursor = await r.table(app.config.DATABASE["receive_asset"])\
                .filter({"idx": receive_asset_state["idx"], "public": receive_asset_state["public"] })\
                .pluck("unique_code")\
                .run(app.config.DB)
    except Exception as e:
        logging.error(f"From receiver_asset_unique_code {e}")
        raise DBError(f"Database Error{e}")
    result = await cursor_to_result(cursor)
    receive_asset_state.update(result)

    return receive_asset_state
