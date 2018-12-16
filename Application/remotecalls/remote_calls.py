import json
import aiohttp
import base64
import asyncio
#from addressing import addresser

from errors.errors import ApiBadRequest
from errors.errors import ApiInternalError

import coloredlogs, logging
coloredlogs.install()


def load_json(data):
    try:
        request_json = json.loads(data)
    except Exception as e:
        raise ApiBadRequest(f"Json cannot be parsed")
    return request_json



async def get_s3_link(url):
    ##request object received from sanic app, It has all the
    ##paramteres sent by the user.
    #url(bytes)
    logging.info(f"URL received in get_s3_link {url}")
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url.decode()) as request_response:
                data = await request_response.read()
        except Exception as e:
            logging.error(f"error {e} in {__file__} ")
            raise ApiInternalError("Error with s3 url")
    return data


async def from_mnemonic(url, mnemonic):
    ##request object received from sanic app, It has all the
    ##paramteres sent by the user.
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(f"http://{url}/from_mnemonic",
                json={'mnemonic': mnemonic
                }) as request_response:
                data = await request_response.read()
        except Exception as e:
            logging.error(f"error {e} in {__file__} ")
            logging.error("Registration api is not working, Please fix it Dude")
            raise ApiInternalError("Registration api is not working, Please fix it Dude")



    request_json = load_json(data)

    master_pub, master_priv, zero_pub, zero_priv = request_json["data"]["master_public_key"],\
                request_json["data"]["master_private_key"], request_json["data"]["zeroth_public_key"],\
                    request_json["data"]["zeroth_private_key"]
    return master_pub, master_priv, zero_pub, zero_priv


async def generate_mnemonic(url):
    ##request object received from sanic app, It has all the
    ##paramteres sent by the user.
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"http://{url}/get_mnemonic") as request_response:
                data = await request_response.read()
        except Exception as e:
            logging.error(f"error {e} in {__file__} ")
            logging.error("Registration api is not working, Please fix it Dude")
            raise ApiInternalError("Registration api is not working, Please fix it Dude")



    request_json = load_json(data)

    master_pub, master_priv, zero_pub, zero_priv, mnemonic= request_json["data"]["master_public_key"],\
                request_json["data"]["master_private_key"], request_json["data"]["zeroth_public_key"],\
                    request_json["data"]["zeroth_private_key"], request_json["data"]["mnemonic"]
    return master_pub, master_priv, zero_pub, zero_priv, mnemonic







async def registration(request):
    ##request object received from sanic app, It has all the
    ##paramteres sent by the user.
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(f"http://{request.app.config.REGISTRATION}/registration",
                json={'email': request.json["email"], "phone_number": request.json["phone_number"],\
                    'adhaar': request.json["adhaar"],'pancard': request.json["pancard"],
                    'first_name': request.json["first_name"], 'last_name': request.json['last_name'],\
                    'user_type': request.json["user_type"]
                }) as request_response:
                data = await request_response.read()
        except Exception as e:
            logging.error("Registration api is not working, Please fix it Dude")
            raise ApiInternalError("Registration api is not working, Please fix it Dude")


    request_json = load_json(data)

    if request_json.get("error"):
        raise ApiBadRequest(f"User already exists")

    user_id, password, secrets = request_json["data"]["user_id"],\
                request_json["data"]["password"], request_json["data"]["secrets"]
    return user_id, password, secrets


async def child_keys(url, mnemonic, child_key_index):

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(f"http://{url}/child_mnemonic_keys",
                json={'mnemonic': mnemonic, "child_key_index": child_key_index\
                }) as request_response:
                data = await request_response.read()
        except Exception as e:
            logging.error("Registration api is not working, Please fix it Dude")
            raise ApiInternalError("Registration api is not working, Please fix it Dude")
    result = load_json(data)
    master_public_key = result["data"]["master_public_key"]
    child_public_key = result["data"]["child_public_key"]
    child_private_key = result["data"]["child_private_key"]
    return master_public_key, child_public_key, child_private_key



async def key_index_keys(app, mnemonic, key_indexes):
    """
    THis is to get public/private key pairs from the key_indexes
    array stored against the user in the Account on blockchain.

    The api that need to be pinged is registration API with /keys_from_indexes
    encpoint with args
            mnemonic
            key_indexes:
                type: list, with each element must be a uint32 type.
    """

    assert all(isinstance(n, int) for n in key_indexes), "All elements in key_indexes should be int"

    async with aiohttp.ClientSession() as session:
            async with session.post(f"http://{app.config.GOAPI_URL}/keys_from_indexes",
                json={'mnemonic': mnemonic, "key_indexes":  key_indexes}) as request_response:
                data = await request_response.read()


    request_json = load_json(data)

    if request_json.get("error"):
        raise Exception("There is some error in getting key pairs from key_indexes")
    return request_json["data"]
