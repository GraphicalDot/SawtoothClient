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
import binascii
from rethinkdb.errors import ReqlNonExistenceError

from errors.errors import ApiBadRequest
from errors.errors import ParentKeysError, DBError

from sanic.log import logging
from encryption.key_derivations import generate_scrypt_key,\
                                    check_bcrypt
from encryption.symmetric import aes_decrypt
#import coloredlogs, logging
#coloredlogs.install()
import coloredlogs, logging
coloredlogs.install()






async def cursor_to_result(cursor):
    result = []
    while (await cursor.fetch_next()):
        item = await cursor.next()
        result.append(item)
    if not result:
        return False
    else:
        return result[0]





async def find_orgnization_account(app, org_name, pancard, email):
    try:
        query = {"pancard": pancard, "org_name": org_name, "email": email}
        cursor = await r.table(app.config.DATABASE["users"])\
            .filter(query)\
            .run(app.config.DB)
    except Exception as e:
        logging.info(f"No account failed with error --<{e}>--")
        raise DBError(f"Database Error{e}")

    return await cursor_to_result(cursor)




##find account on the basis of any key like user_id
async def find_on_key(app, key, value):
    try:
        cursor = await r.table(app.config.DATABASE["users"])\
            .filter(r.row[key] == value)\
            .run(app.config.DB)
    except Exception as e:
        return False

    return await cursor_to_result(cursor)


async def find_on_key(app, key, value):
    try:
        cursor = await r.table(app.config.DATABASE["users"])\
            .filter(r.row[key] == value)\
            .run(app.config.DB)
    except Exception as e:
        return False

    return await cursor_to_result(cursor)



async def insert_otps(app, _type, otp, user_id, value, validity):
    ##TODO make provision to block sending otp after 5 tries/
    try:
        if _type == "email":
            data = {
                "email_otp": otp,
                "user_id": user_id,
                "validity": validity,
                "otp_verified": False,
                "email": value
                }

            logging.info(data)
            f = await r.table(app.config.DATABASE["otp_email"])\
                .insert(data, conflict="update")\
                .run(app.config.DB)

        else:
            data = {
                "mobile_otp": otp,
                "user_id": user_id,
                "validity": validity,
                "otp_verified": False,
                "phone_number": value
                }
            logging.info(data)

            f = await r.table(app.config.DATABASE["otp_mobile"])\
                .insert(data,   conflict="update")\
                .run(app.config.DB)
        logging.info(f"Insert otp data successful with message --<{f}>--")
    except Exception as e:
        logging.error(f"Insert otp  in {_type} failed with error --<{e}>--")

    return


async def find_email_otp(app, email):
    try:
        cursor = await r.table(app.config.DATABASE["otp_email"])\
            .filter(r.row["email"] == email)\
            .run(app.config.DB)
    except Exception as e:
        return False

    return await cursor_to_result(cursor)



async def find_mobile_otp(app, phone_number):
    try:
        cursor = await r.table(app.config.DATABASE["otp_mobile"])\
            .filter(r.row["phone_number"] == phone_number)\
            .run(app.config.DB)
    except Exception as e:
        return False

    return await cursor_to_result(cursor)

async def account_verified(app, email, phone_number):
    await r.table(app.config.DATABASE["otp_email"])\
        .filter({"email": email})\
        .update({"otp_verified": True})\
        .run(app.config.DB)

    await r.table(app.config.DATABASE["otp_mobile"])\
        .filter({"phone_number": phone_number})\
        .update({"otp_verified": True})\
        .run(app.config.DB)





async def update_create_asst_idxs(app, user_id, index):
    return await r.table(app.config.DATABASE["users"])\
            .filter({"user_id": user_id})\
            .update({"create_asset_idxs": r.row["create_asset_idxs"].append(index)})\
            .run(app.config.DB)


async def update_create_asst_idxs_pending(app, user_id, index):
    return await r.table(app.config.DATABASE["pending_users"])\
            .filter({"user_id": user_id})\
            .update({"create_asset_idxs": r.row["create_asset_idxs"].append(index)})\
            .run(app.config.DB)



async def update_password(app, email, h_password, salt, encrypted_mnemonic):
    return await r.table(app.config.DATABASE["users"])\
            .filter({"email": email})\
            .update({"password": h_password, "salt": salt,
                    "encrypted_mnemonic": encrypted_mnemonic}, return_changes=True)\
            .run(app.config.DB)



async def update_flt_acc_idxs(app, user_id, index):
    return await r.table(app.config.DATABASE["users"])\
            .filter({"user_id": user_id})\
            .update({"float_account_idxs": r.row["float_account_idxs"]\
            .append(index)})\
            .run(app.config.DB)


async def update_child_account_idxs(app, user_id, index):
    return await r.table(app.config.DATABASE["users"])\
            .filter({"user_id": user_id})\
            .update({"child_account_idxs": r.row["child_account_idxs"]\
            .append(index)})\
            .run(app.config.DB)




async def update_receive_assets_idxs(app, user_id, index):
    return await r.table(app.config.DATABASE["users"])\
            .filter({"user_id": user_id})\
            .update({"receive_asset_idxs": r.row["receive_asset_idxs"]\
            .append(index)})\
            .run(app.config.DB)

async def update_share_asset_idxs(app, user_id, index):
    return await r.table(app.config.DATABASE["users"])\
            .filter({"user_id": user_id})\
            .update({"share_asset_idxs": r.row["share_asset_idxs"]\
            .append(index)})\
            .run(app.config.DB)

##insert newly create organization account
async def insert_account(app, data):

    if not data:
        logging.info("Empty data cannot be insrted into the Database")
        return
    try:
        f = await r.table(app.config.DATABASE["users"])\
                .insert(data)\
                .run(app.config.DB)

    except Exception as e:
        logging.error(f"Insert account failed with error --<{e}>--")
        raise DBError(e)
    return



async def claim_account(app, user_id, email, phone_number, indian_time):
    """
    This will be called when the user claims its pending account on pending_users
    table, The account should already have been created in users table and now
    same user in pending_users table must be updated with "claimed_by": users_zero_pub
    claimed: True, claimed_on: Time stamp

    """
    result =  await r.table(app.config.DATABASE["pending_users"])\
            .filter({"user_id": user_id, "email": email, "phone_number": phone_number})\
            .update({"claimed": True, "claimed_on": indian_time})\
            .run(app.config.DB)

    logging.info(f"Result after updating pending user table for {user_id} is {result}")
    if not bool(result):
        raise Exception("User coudnt be found in Pending table")
    return



##will be used when the use tries to login
async def fetch_info_by_email(email, app):
    try:
        cursor = await r.table(app.config.DATABASE["users"])\
            .filter({"email": email})\
            .run(app.config.DB)
    except ReqlNonExistenceError:
        raise ApiBadRequest(
            f"No account with this email exists {email} or the user havent claimed his/her account")
    except Exception as e:
        print (e)

    result = []
    while (await cursor.fetch_next()):
        item = await cursor.next()
        result.append(item)
    if not result:
        raise ApiBadRequest(
            f"No account with this email  exists {email} or the user havent claimed his/her account")
    else:
        return result[0]


async def get_field(app, user_id, field_name):
    try:
        cursor = await r.table(app.config.DATABASE["users"])\
            .filter(r.row["user_id"] == user_id)\
            .pluck(field_name)\
            .run(app.config.DB)
    except Exception as e:
        return False

    return await cursor_to_result(cursor)


##find account on the basis of any key like user_id
async def find_user_email_otp(app, key, value):
    try:
        cursor = await r.table(app.config.DATABASE["otp"])\
            .filter(r.row[key] == value)\
            .run(app.config.DB)
    except Exception as e:
        return False

    return await cursor_to_result(cursor)


async def find_user_mobile_otp(app, key, value):
    try:
        cursor = await r.table(app.config.DATABASE["mobile_otp"])\
            .filter(r.row[key] == value)\
            .run(app.config.DB)
    except Exception as e:
        return False

    return await cursor_to_result(cursor)


######################################################################################










async def find_user(app, phone_number, email):
    cursor = await r.table(app.config.DATABASE["users"])\
            .filter({"email": email, "phone_number": phone_number})\
            .run(app.config.DB)
    return await cursor_to_result(cursor)


async def pending_find_on_key(key, value, app):
    """
    Find key value pair in pending users table
    """
    try:
        cursor = await r.table(app.config.DATABASE["pending_users_table"])\
            .filter(r.row[key] == value)\
            .run(app.config.DB)
    except Exception as e:
        return False

    return await cursor_to_result(cursor)





















async def fetch_all_account_resources(conn):
    return await r.table('accounts')\
        .filter((fetch_latest_block_num() >= r.row['start_block_num'])
                & (fetch_latest_block_num() < r.row['end_block_num']))\
        .map(lambda account: account.merge(
            {'publicKey': account['public_key']}))\
        .map(lambda account: account.merge(
            {'holdings': fetch_holdings(account['holdings'])}))\
        .map(lambda account: (account['label'] == "").branch(
            account.without('label'), account))\
        .map(lambda account: (account['description'] == "").branch(
            account.without('description'), account))\
        .without('public_key', 'delta_id',
                 'start_block_num', 'end_block_num')\
        .coerce_to('array').run(conn)


async def fetch_account_resource(conn, public_key, auth_key):
    try:
        return await r.table('accounts')\
            .get_all(public_key, index='public_key')\
            .max('start_block_num')\
            .merge({'publicKey': r.row['public_key']})\
            .merge({'holdings': fetch_holdings(r.row['holdings'])})\
            .do(lambda account: (r.expr(auth_key).eq(public_key)).branch(
                account.merge(_fetch_email(public_key)), account))\
            .do(lambda account: (account['label'] == "").branch(
                account.without('label'), account))\
            .do(lambda account: (account['description'] == "").branch(
                account.without('description'), account))\
            .without('public_key', 'delta_id',
                     'start_block_num', 'end_block_num')\
            .run(conn)
    except ReqlNonExistenceError:
        raise ApiBadRequest(
            "No account with the public key {} exists".format(public_key))


def _fetch_email(public_key):
    return r.table('auth')\
        .get_all(public_key, index='public_key')\
        .pluck('email')\
        .coerce_to('array')[0]
