# Copyright 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

import rethinkdb as r
from rethinkdb.errors import ReqlNonExistenceError
from errors.errors import ApiBadRequest, AccountCreationError, \
            AssetCreationError, DBError
#from db.accounts_query import find_user_field, find_on_key, cursor_to_result



import coloredlogs, logging
coloredlogs.install()


async def find_transfer_asset(app, issuer_address, receiver_address):
    try:
        cursor = await r.table(app.config.DATABASE["transfer_asset"])\
            .filter({"receiver_address": receiver_address,
                "issuer_address": issuer_address})\
            .run(app.config.DB)
    except Exception as e:
        logging.info(f"No account failed with error --<{e}>--")
        raise DBError(f"Database Error{e}")

    return await cursor_to_result(cursor)




async def store_transfer_assets(app, data):
    logging.info(f"This is the data for store_transfer_assets {data}")
    if await find_transfer_asset(app, data["issuer_address"],
                                        data["receiver_address"]):
        logging.error("This transfer_asset transaction is already present in\
                the database")
        raise Exception("This transfer_asset transaction is already present in\
                the database")

    try:
        return await r.table(app.config.DATABASE["transfer_asset"])\
            .insert(data).run(app.config.DB)
    except ReqlNonExistenceError as e:
        logging.error(f"Error in inserting {data} which is {e}")
        raise ApiBadRequest(
            f"Error in storing asset {e}")

    return
