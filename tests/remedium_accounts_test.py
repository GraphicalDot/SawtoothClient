

# Third-party imports...
from nose.tools import assert_true, assert_false, assert_equals
from nose.tools import assert_is_not_none
import requests
from test_static import user1, user2, user3, user4, user5, user6, USER_REGISTRATION, conn
from test_apis import AccountApis
instance = AccountApis()
import json
import coloredlogs, logging
coloredlogs.install()

FRESH_START= False
import asyncio
import aiohttp
import rethinkdb as ret

"""

"""

def db_find_on_key(email):
    try:
        result = ret.table("users").filter(ret.row["email"]==email).run(conn).items[0]
        return result, True
    except Exception as e:
        #logging.error(e)
        return False, False


async def boilerplate_user_registration(user):
    response = await AccountApis.register_user(user)

    db_entry, user_flag = db_find_on_key(user["email"])

    ##if requster is a child, check whether the account have child_zero_pub or not
    if response.status_code == 200:
        logging.info(f"Registering user {user['first_name']} for the first time")
        # If the request is sent successfully, then I expect a response to be returned.
        assert_equals(user_flag, True)

    elif response.status_code == 400:

        logging.error(response.json())
        assert_equals(user_flag, True)


    else:
        logging.error(f"response is <{response.json()}> and error code {response.status_code}")



async def boilerplate_share_mnemonic(user, email_list):
    response = await AccountApis.share_mnemonic(user, email_list)


    ##if requster is a child, check whether the account have child_zero_pub or not
    if response.status_code == 200:
        logging.info(f"Sharing menmonic of {user} with other user {email_list}")
        # If the request is sent successfully, then I expect a response to be returned.

    elif response.status_code == 400:
        logging.error(response.json())


    else:
        logging.error(f"response is <{response.json()}> and error code {response.status_code}")

# Define a coroutine that takes in a future

# Spin up a quick and simple event loop
# and run until completed
loop = asyncio.get_event_loop()

async def test_register_users():
    async with aiohttp.ClientSession() as session:
        f = await asyncio.gather(*[
            boilerplate_user_registration(user)
                 for user in [user1, user2, user3, user4, user5, user6]
        ])

    return f



async def test_share_mnemonic():
    await boilerplate_share_mnemonic(user1, [user2["email"], user3["email"], user4["email"], user5["email"]])



try:
    #asyncio.ensure_future(test_register_users())
    loop.run_until_complete(test_register_users())
    loop.run_until_complete(test_share_mnemonic())

finally:
    loop.close()
