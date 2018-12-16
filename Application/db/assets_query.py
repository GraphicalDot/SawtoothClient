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

from errors.errors import ApiBadRequest, AccountCreationError, AssetCreationError

from db.accounts_query import find_user_field, find_on_key, cursor_to_result



import coloredlogs, logging
coloredlogs.install()


async def update_issuer_asset(app, asset_address, data):
    return await r.table(app.config.DATABASE["assets"])\
            .filter({"asset_address": asset_address})\
            .update({
                "ownership_transfer": data["receiver_address"],
                "transferred_on": data["indiantime"],
                "transfer_transaction_id": data["transaction_id"],
                "transfer_batch_id": data["batch_id"]
                })\
            .run(app.config.DB)



async def update_receiver_asset(app, asset_address, data):
    return await r.table(app.config.DATABASE["assets"])\
            .filter({"asset_address": asset_address})\
            .update({
                "key": data["key"],
                "url": data["url"],
                "file_name": data["file_name"],
                "file_hash": data["file_hash"],
                "master_key": data["master_key"],
                "master_url": data["master_url"],
                "ownership_received": data["issuer_address"],
                "received_on": data["indiantime"],
                "transfer_transaction_id": data["transaction_id"],
                "transfer_batch_id": data["batch_id"]
                })\
                .run(app.config.DB)



async def update_issuer_asset_shared(app, asset_address, index):
    return await r.table(app.config.DATABASE["assets"])\
            .filter({"asset_address": asset_address})\
            .update({"shared_with": r.row["shared_with"].append(index)})\
            .run(app.config.DB)


async def store_assets(app, data):
    """
    if not await find_on_key("user_id", data["user_id"], app):
        raise AccountCreationError(
            message=f"user with user_id={data['user_id']} doesnt exists"
        )
    if await find_user_field(app, data["user_id"], "file_hash") == data["file_hash"]:
        raise AssetCreationError(
            message=f"Asset with file_hash=data['file_hash'] already exists"
        )
    """
    try:
        return await r.table(app.config.DATABASE["assets"])\
            .insert(data).run(app.config.DB)
    except ReqlNonExistenceError as e:
        raise ApiBadRequest(
            f"Error in storing asset {e}")


async def retrieve_assets(user_id, conn):
    try:
        cursor= await r.table('assets')\
            .filter(r.row["user_id"] == user_id)\
            .run(conn)
    except ReqlNonExistenceError:
        raise ApiBadRequest(
            f"No account with this user_id exists {user_id}")

    assets = []
    while (await cursor.fetch_next()):
        item = await cursor.next()
        assets.append(item)
    return assets


async def check_filehash_assets(file_hash, conn):
    try:
        cursor= await r.table('assets')\
            .filter(r.row["file_hash"] == file_hash)\
            .run(conn)
    except ReqlNonExistenceError:
        raise ApiBadRequest(
            f"No account with this user_id exists {user_id}")

    assets = []
    while (await cursor.fetch_next()):
        item = await cursor.next()
        assets.append(item)

    logging.debug(f"assets found with similar hash are {assets}")
    if len(assets) > 0:
        return False
    return True
