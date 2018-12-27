


from protocompiled import float_account_pb2, account_pb2, asset_pb2, \
                organization_account_pb2, child_account_pb2, receive_asset_pb2, \
                share_asset_pb2, user_pb2, share_secret_pb2
from google.protobuf.json_format import MessageToDict
import requests
import json
import coloredlogs, logging
import aiohttp
import base64
import asyncio
coloredlogs.install()
from addressing import addresser



def load_json(data):
    try:
        request_json = json.loads(data)
    except CustomError as e:
        raise ApiBadRequest(f"Json cannot be parsed")
    return request_json



async def address_state(REST_API_URL, address):
    async with aiohttp.ClientSession() as session:
            async with session.get(f"http://{REST_API_URL}/state/{address}") as request_response:
                data = await request_response.read()


    request_json = load_json(data)

    if request_json.get("error"):
        logging.error("State is not present on the blockchain")
        return False
    return base64.b64decode(request_json["data"])

async def deserialize_float_account(REST_API_URL, address):
        state_data = await address_state(REST_API_URL, address)
        ##decoding data stored on the
        flt_acc = float_account_pb2.FloatAccount()
        flt_acc.ParseFromString(state_data)
        float_account = MessageToDict(flt_acc, preserving_proto_field_name=True)
        float_account.update({"address": address})

        ##this is to handle accounts which havent claimed their account
        if float_account.get("claimed_by"):
            account_address = addresser.create_organization_account_address(
                    float_account["claimed_by"], 0)
        else:
            account_address = None
            data = {"claimed": None,
                "claimed_by": None,
                "claimed_on": None}

            float_account.update(data)

        float_account.update({"account_address": account_address})
        if not float_account.get("child_zero_pub"):
            float_account.update({"child_zero_pub": None})

        return float_account



##TODO this must be deleted
async def deserialize_child(REST_API_URL, address):

        state_data = await address_state(REST_API_URL, address)
        ##decoding data stored on the blockchain
        if not state_data:
            return False
        acc = child_account_pb2.ChildAccount()
        acc.ParseFromString(state_data)
        account = MessageToDict(acc, preserving_proto_field_name=True)
        account.update({"address": address})
        return account

async def deserialize_user(REST_API_URL, address):
        state_data = await address_state(REST_API_URL, address)
        ##decoding data stored on the blockchain
        if not state_data:
            return False
        acc = user_pb2.UserAccount()
        acc.ParseFromString(state_data)
        account = MessageToDict(acc, preserving_proto_field_name=True)
        account.update({"address": address})
        return account


async def deserialize_org_account(REST_API_URL, address):
        logging.info(f"Now deserializing organization account present on {address}")

        state_data = await address_state(REST_API_URL, address)
        ##decoding data stored on the blockchain
        if not state_data:
            return False
        acc = organization_account_pb2.OrganizationAccount()
        acc.ParseFromString(state_data)
        account = MessageToDict(acc, preserving_proto_field_name=True)
        account.update({"address": address})

        return account

async def deserialize_share_secret(REST_API_URL, address):
        logging.info(f"Now deserializing share_secret present on {address}")
        state_data = await address_state(REST_API_URL, address)
        ##decoding data stored on the blockchain
        if not state_data:
            return False
        acc = share_secret_pb2.ShareSecret()
        acc.ParseFromString(state_data)
        asset = MessageToDict(acc, preserving_proto_field_name=True)
        asset.update({"address": address})
        return asset

async def deserialize_receive_secret(REST_API_URL, address):
        logging.info(f"Now deserializing receive_secret  present on {address}")
        state_data = await address_state(REST_API_URL, address)
        ##decoding data stored on the blockchain
        if not state_data:
            return False
        acc = receive_secret_pb2.ReceiveSecret()
        acc.ParseFromString(state_data)
        asset = MessageToDict(acc, preserving_proto_field_name=True)
        asset.update({"address": address})
        return asset

async def deserialize_asset(REST_API_URL, address):
        logging.info(f"Now deserializing asset present on {address}")
        state_data = await address_state(REST_API_URL, address)
        ##decoding data stored on the blockchain
        if not state_data:
            logging.error(f"No asset data present corresponding to {address}")
            return False
        acc = asset_pb2.Asset()
        acc.ParseFromString(state_data)
        asset = MessageToDict(acc, preserving_proto_field_name=True)

        ##This is True, implies this asset has been created by the owner ot its
        ##child but havent been transffered to anyone else
        if not asset.get("ownership_received"):
                data = {"ownership_received": None,
                        "received_on": None,
                        "parent_address": None,
                        "issuer_child_zero_pub": None}
                asset.update(data)

        if not asset.get("child_zero_pub"):
            asset.update({"child_zero_pub": None})

        asset.update({"address": address})

        return asset


async def deserialize_receive_asset(REST_API_URL, address):
        logging.info(f"Now deserializing receive_asset present on {address}")
        state_data = await address_state(REST_API_URL, address)
        ##decoding data stored on the blockchain
        if not state_data:
            return False
        acc = receive_asset_pb2.ReceiveAsset()
        acc.ParseFromString(state_data)
        asset = MessageToDict(acc, preserving_proto_field_name=True)
        asset.update({"address": address})
        return asset


async def deserialize_share_asset(REST_API_URL, address):
        logging.info(f"Now deserializing share_asset present on {address}")
        state_data = await address_state(REST_API_URL, address)
        ##decoding data stored on the blockchain
        if not state_data:
            return False
        acc = share_asset_pb2.ShareAsset()
        acc.ParseFromString(state_data)
        asset = MessageToDict(acc, preserving_proto_field_name=True)
        asset.update({"address": address})
        return asset


def synchronous_deserialize_flt_account(REST_API_URL, address):
        r = requests.get(f"{REST_API_URL}/state/{address}")

        if r.json()["data"]:
            acc = float_account_pb2.FloatAccount()
            acc.ParseFromString(base64.b64decode(r.json()["data"]))
            account = MessageToDict(acc, preserving_proto_field_name=True)
        else:
            return False
        ##decoding data stored on the blockchain
        return account



def synchronous_deserialize_account(REST_API_URL, address):
        r = requests.get(f"{REST_API_URL}/state/{address}")

        if r.json()["data"]:
            acc = account_pb2.Account()
            acc.ParseFromString(base64.b64decode(r.json()["data"]))
            account = MessageToDict(acc, preserving_proto_field_name=True)
        else:
            return False
        ##decoding data stored on the blockchain
        return account




def synchronous_deserialize_asset(REST_API_URL, address):
        r = requests.get(f"{REST_API_URL}/state/{address}")

        if r.json()["data"]:
            acc = asset_pb2.Asset()
            acc.ParseFromString(base64.b64decode(r.json()["data"]))
            asset = MessageToDict(acc, preserving_proto_field_name=True)
        else:
            return False
        ##decoding data stored on the blockchain
        return asset
