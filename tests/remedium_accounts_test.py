

# Third-party imports...
from nose.tools import assert_true, assert_false, assert_equals
from nose.tools import assert_is_not_none
import requests
from test_static import user1, user2, user3, user4, user5, user6, USER_REGISTRATION, conn
from test_apis import AccountApis, SecretAPIS
instance = AccountApis()
import json
import coloredlogs, logging
coloredlogs.install()

FRESH_START= False
import asyncio
import aiohttp
import rethinkdb as ret

receive_secret_addresses = {}
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



async def boilerplate_share_mnemonic(user, receive_secret_addresess):
    logging.info(f"Starting to execute share mnemonic by user {user}")
    response = await AccountApis.share_mnemonic(user, receive_secret_addresess)


    ##if requster is a child, check whether the account have child_zero_pub or not
    if response.status_code == 200:
        logging.info(f"Sharing menmonic of {user} with other user {receive_secret_addresess}")
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




async def boilerplate_all_shares(user):
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




async def boilerplate_receive_secret(user):
    instance = await SecretAPIS()
    response = await instance.create_receive_secret(user)
    logging.info(json.dumps(response.json()["data"], indent=10))


async def boilerplate_get_account(user):
    instance = await AccountApis()
    response = await instance.get_account(user)
    logging.info(json.dumps(response.json()["data"], indent=10))

async def boilerplate_get_receive_secrets(user):
    instance = await SecretAPIS()
    response = await instance.get_receive_secrets(user)
    logging.info(json.dumps(response.json()["data"], indent=10))
    return response.json()["data"]

async def boilerplate_execute_share_mnemonic(user, receive_secret_address):
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
    instance = await SecretAPIS()
    execution_response = await instance.get_shares_on_receive_secrets(user, receive_secret_address)

    logging.info(json.dumps(execution_response.json(), indent=4))
    ##the share_secret address whose ownership is with receive_secret_address
    share_secret_address = execution_response.json()["data"][0]["share_secret_address"]
    logging.info("THis is the shared secret adress %s"%json.dumps(share_secret_address, indent=10))

    res = await instance.execute_share_secret(user, receive_secret_address, share_secret_address)
    logging.info(json.dumps(res.json(), indent=4))

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
    logging.info(f"THis is receive_secret_addresses {receive_secret_addresses}")
    await boilerplate_share_mnemonic(user1, [e[0] for e in receive_secret_addresses.values()])
    logging.info(f"THis is receive_secret_addresses {receive_secret_addresses}")


async def test_activate_mnemonic():
    await boilerplate_activate_mnemonic(user1)



async def test_get_all_shares():
    await boilerplate_all_shares(user1)



async def test_create_receive_secret_usr2():
    await boilerplate_receive_secret(user2)
    await boilerplate_receive_secret(user2)


async def test_create_receive_secret_usr3():
    await boilerplate_receive_secret(user3)
    await boilerplate_receive_secret(user3)


async def test_create_receive_secret_usr4():
    await boilerplate_receive_secret(user4)
    await boilerplate_receive_secret(user4)


async def test_create_receive_secret_usr5():
    await boilerplate_receive_secret(user5)
    await boilerplate_receive_secret(user5)


async def test_get_account():
    await boilerplate_get_account(user2)


async def test_get_receive_secrets_usr2():
    result = await boilerplate_get_receive_secrets(user2)
    global receive_secret_addresses
    receive_secret_addresses.update({"user2": [e["address"] for e in result]})

async def test_get_receive_secrets_usr3():
    result = await boilerplate_get_receive_secrets(user3)
    global receive_secret_addresses
    receive_secret_addresses.update({"user3": [e["address"] for e in result]})


async def test_get_receive_secrets_usr4():
    result = await boilerplate_get_receive_secrets(user4)
    global receive_secret_addresses
    receive_secret_addresses.update({"user4": [e["address"] for e in result]})


async def test_get_receive_secrets_usr5():
    result = await boilerplate_get_receive_secrets(user5)
    global receive_secret_addresses
    receive_secret_addresses.update({"user5": [e["address"] for e in result]})


async def test_execute_share_mnemonic_2():
    await boilerplate_execute_share_mnemonic(user2,  receive_secret_addresses["user2"][0])



async def test_execute_share_mnemonic_3():
    await boilerplate_execute_share_mnemonic(user3, receive_secret_addresses["user3"][0])


async def test_execute_share_mnemonic_4():
    await boilerplate_execute_share_mnemonic(user4, receive_secret_addresses["user4"][0])


async def test_execute_share_mnemonic_5():
    await boilerplate_execute_share_mnemonic(user5, receive_secret_addresses["user5"][0])


try:
    #asyncio.ensure_future(test_register_users())
    loop.run_until_complete(test_register_users())
    """
    loop.run_until_complete(test_create_receive_secret_usr2())
    loop.run_until_complete(test_create_receive_secret_usr3())
    loop.run_until_complete(test_create_receive_secret_usr4())
    loop.run_until_complete(test_create_receive_secret_usr5())
    """


    loop.run_until_complete(test_get_receive_secrets_usr2())
    loop.run_until_complete(test_get_receive_secrets_usr3())
    loop.run_until_complete(test_get_receive_secrets_usr4())
    loop.run_until_complete(test_get_receive_secrets_usr5())
    loop.run_until_complete(test_get_account())

    #loop.run_until_complete(test_share_mnemonic())

    #loop.run_until_complete(test_activate_mnemonic())
    #loop.run_until_complete(test_execute_share_mnemonic_2())
    #loop.run_until_complete(test_execute_share_mnemonic_3())
    #loop.run_until_complete(test_execute_share_mnemonic_4())
    #loop.run_until_complete(test_execute_share_mnemonic_5())
    loop.run_until_complete(test_get_all_shares())

finally:
    loop.close()


logging.info(receive_secret_addresses)
