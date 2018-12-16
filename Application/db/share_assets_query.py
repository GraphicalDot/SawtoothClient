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
from db.accounts_query import find_user_field, find_on_key, cursor_to_result



import coloredlogs, logging
coloredlogs.install()


async def find_share_asset(app, asset_address, receive_asset_address):
    """
    asset_address is the original asset address which was shared with
    account_address

    """
    try:
        cursor = await r.table(app.config.DATABASE["share_asset"])\
            .filter({"original_asset_address": asset_address,
                "receive_asset_address": receive_asset_address})\
            .run(app.config.DB)
    except Exception as e:
        logging.info(f"No account failed with error --<{e}>--")
        return False

    ##cursor to result returns False if no data was found
    return await cursor_to_result(cursor)




async def store_share_asset(app, data):
    ##you need to encode binary data into string

    try:
        return await r.table(app.config.DATABASE["share_asset"])\
            .insert(data).run(app.config.DB)
    except ReqlNonExistenceError as e:
        logging.error(f"Error in inserting {data} which is {e}")
        raise ApiBadRequest(
            f"Error in storing asset {e}")

    return
