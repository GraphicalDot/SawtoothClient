



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


async def get_shared_secret_array(app, user_id):

    try:
        cursor= await r.table(app.config.DATABASE["users"])\
            .filter({"user_id": user_id})\
            .pluck({"shared_secret"})\
            .run(app.config.DB)

    except ReqlNonExistenceError as e:
        logging.error(f"Error in inserting {data} which is {e}")
        raise ApiBadRequest(
            f"Error in storing asset {e}")

    return await cursor_to_result(cursor)


async def update_share_mnemonic(app, trans):
    return await r.table(app.config.DATABASE["share_mnemonic"])\
            .filter({"user_id": trans["user_id"], "shared_secret_address": trans["share_secret_address"]})\
            .update({"reset_key": trans["reset_key"].decode(),\
                    "updated_on": trans["timestamp"],
                    "active": True,
            "reset_salt": trans["salt"].decode()})\
            .run(app.config.DB)


async def update_mnemonic_encryption_salt(app, user_id, mnemonic_encryption_salt):
    return await r.table(app.config.DATABASE["users"])\
            .filter({"user_id": user_id})\
            .update({"org_mnemonic_encryption_salt": mnemonic_encryption_salt})\
            .run(app.config.DB)



async def get_addresses_on_ownership(app, owner_account_address):
    #fetch shared_secret contracts on the basis of the ownerhsip
    ##since the originla user floats a smart contract to different users directing
    ##to their account addresses, this function will fecth these share_secret contract
    ##for toher users who want to update this shared_secret address with the reset_key

    try:
        cursor= await r.table(app.config.DATABASE["share_mnemonic"])\
            .filter({"ownership": owner_account_address})\
            .run(app.config.DB)

    except ReqlNonExistenceError as e:
        logging.error(f"Error in inserting {data} which is {e}")
        raise ApiBadRequest(
            f"Error in storing asset {e}")

    return await cursor_to_result(cursor)
