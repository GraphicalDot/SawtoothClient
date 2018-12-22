



import rethinkdb as r
from rethinkdb.errors import ReqlNonExistenceError
from errors.errors import CustomError
from db.accounts_query import find_on_key, cursor_to_result



import coloredlogs, logging
coloredlogs.install()



async def store_share_mnemonics(app, data):
    if not await find_on_key(app, "user_id", data["user_id"]):
        raise CustomError(f"This user account couldnt be found user_id <<{data['user_id']}>>")

    try:
        return await r.table(app.config.DATABASE["share_mnemonic"])\
            .insert(data).run(app.config.DB)
        logging.info(data)

    except ReqlNonExistenceError as e:
        logging.error(f"Error in inserting {data} which is {e}")
        raise ApiBadRequest(
            f"Error in storing asset {e}")

    return


async def update_shared_secret_array(app, user_id, array):
    return await r.table(app.config.DATABASE["users"])\
            .filter({"user_id": user_id})\
            .update({"shared_secret": array})\
            .run(app.config.DB)
