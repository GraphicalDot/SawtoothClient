

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


def otp_email(requester):
    try:
        result = ret.db('remediumdb').table('otp_email').filter({"email": requester["email"]}).run(conn).items[0]["email_otp"]
        return result
    except Exception as e:
        #logging.error(e)
        return False



def otp_mobile(requester):
    try:
        result = ret.db('remediumdb').table('otp_mobile').filter({"phone_number": requester["phone_number"]}).run(conn).items[0]["mobile_otp"]
        return result
    except Exception as e:
        #logging.error(e)
        return False


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

        logging.error(user)
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


async def boilerplate_activate_mnemonic(user):
    instance = await AccountApis()
    response = await instance.get_otps(user)
    assert_equals(response.status_code, 200)
    _otp_email = otp_email(user)
    _otp_mobile = otp_mobile(user)

    logging.info(_otp_email)
    logging.info(_otp_mobile)

    f_response = await instance.forgot_password(user, _otp_email, _otp_mobile)
    logging.info(f_response)




async def boilerplate_execute_share_mnemonic(user):
    ##Since shasred_secret addresses has been floated by our main user1, to several
    ##other users like user2, user3, user4,. and user5

    ##THe above function boilerplate_activate_mnemonic floats another kind of smart
    ##contact called as activate_shares, which then creates new scrypt keys with different salts
    ##these salts are stored only in the database, the forgot_pasword api then updates every
    ##shared_secret array of its account, with new reset keys and set active flag of every
    ##sharet_secret contract to True,

    ##now users 2, 3, 4, 5, will loginto their account fetch shared_Secret conracts shared with them
    ## decrypt reset_key and secret share with their public key and then encrypts shared_secret
    ##with the new reset_key and stored it into secret_share again

    ##first we need to get what all share secrets have been shared with him
    instance = await AccountApis()
    response = await instance.all_share_secrets(user)
    logging.info(json.dumps(response.json()["data"], indent=10))


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


async def test_activate_mnemonic():
    await boilerplate_activate_mnemonic(user1)



async def test_execute_share_mnemonic():
    await boilerplate_execute_share_mnemonic(user2)


try:
    #asyncio.ensure_future(test_register_users())
    loop.run_until_complete(test_register_users())
    #loop.run_until_complete(test_share_mnemonic())
    #loop.run_until_complete(test_activate_mnemonic())
    loop.run_until_complete(test_execute_share_mnemonic())


finally:
    loop.close()
