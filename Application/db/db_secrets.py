



import rethinkdb as r
from rethinkdb.errors import ReqlNonExistenceError
from errors.errors import CustomError, ApiInternalError
from db.accounts_query import find_on_key, cursor_to_result



import coloredlogs, logging
coloredlogs.install()

from asyncinit import asyncinit



@asyncinit
class DBSecrets(object):
    async def __init__(self, app, table_name=None,
                        array_name=None):
        #self.val = await self.deferredFn(param)
        ##array_name is the key in the user entry in users table
        ##table_name could be any new table name, in this case it is
        ##
        self.app = app
        self.table_name = self.app.config.DATABASE[table_name]
        self.array_name = array_name
        self.user_table = self.app.config.DATABASE["users"]

    async def store(self, user_id, data):
        if not await find_on_key(self.app, "user_id", user_id):
            raise CustomError(f"This user account couldnt be found user_id <<{user_id}>>")

        try:
            result = await r.table(self.table_name)\
                .insert(data).run(self.app.config.DB)

        except ReqlNonExistenceError as e:
            msg = f"Storing {self.table_name} failed with an error {e}"
            logging.error(msg)
            raise ApiInternalError(msg)

        logging.info(f"Store {self.table_name} successful with messege {result}")
        return result


    async def update_array_with_value(self, user_id, value):
        try:
            result = await r.table(self.user_table)\
                .filter({"user_id": user_id})\
                .update({self.array_name: r.row[self.array_name].append(value)})\
                .run(self.app.config.DB)

        except Exception as e:
            msg = f"Updating {self.table_name} array of user failed with {e}"
            logging.error(msg)
            raise ApiInternalError(msg)
        logging.info(f"Updating {self.array_name} array user sucessful with {result}")
        return result


    async def get_array(self, user_id):

        try:
            cursor= await r.table(self.user_table)\
                .filter({"user_id": user_id})\
                .pluck({self.array_name})\
                .run(self.app.config.DB)

        except ReqlNonExistenceError as e:
            logging.error(f"Error in fetching {data} which is {e}")
            raise ApiBadRequest(
                f"Error in fetching entries from {self.table_name} {e}")

        return await cursor_to_result(cursor)









async def store_data(app, table_name, user_id, data):
    if not await find_on_key(app, "user_id", user_id):
        raise CustomError(f"This user account couldnt be found user_id <<{user_id}>>")

    try:
        result = await r.table(table_name)\
            .insert(data).run(app.config.DB)

    except ReqlNonExistenceError as e:
        logging.error(f"Error in inserting {data} which is {e}")
        raise ApiBadRequest(
            f"Error in storing asset {e}")

    logging.info(f"Storing receive secret transaction {data} successful")
    return result


async def update_array_with_index(app, table_name, user_id, array_name, value):

    return await r.table(table_name)\
            .filter({"user_id": user_id})\
            .update({array_name: r.row[array_name].append(value)})\
            .run(app.config.DB)


async def get_array(app, table_name, user_id, array_name):

    try:
        cursor= await r.table(table_name)\
            .filter({"user_id": user_id})\
            .pluck(array_name)\
            .run(app.config.DB)

    except ReqlNonExistenceError as e:
        logging.error(f"Error in inserting {data} which is {e}")
        raise ApiBadRequest(
            f"Error in storing asset {e}")

    return await cursor_to_result(cursor)



"""
async def update_share_mnemonic(app, trans):
    return await r.table(app.config.DATABASE["share_mnemonic"])\
            .filter({"user_id": trans["user_id"], "shared_secret_address": trans["share_secret_address"]})\
            .update({"reset_key": trans["reset_key"].decode(),\
                    "updated_on": trans["timestamp"],
                    "active": True,
            "reset_salt": trans["salt"].decode()})\
            .run(app.config.DB)


async def update_mnemonic_encryption_salt(app, user_id,salt_one, salt_two):
    return await r.table(app.config.DATABASE["users"])\
            .filter({"user_id": user_id})\
            .update({"org_mnemonic_encryption_salt_one": salt_one,
                "org_mnemonic_encryption_salt_two": salt_two})\
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
"""
