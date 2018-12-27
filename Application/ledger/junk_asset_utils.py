

from google.protobuf.json_format import MessageToDict
import random
from proto import asset_pb2
from sawtooth_signing import create_context
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from sawtooth_signing.secp256k1 import Secp256k1PublicKey
import binascii
import random
import hashlib



def sign_nonce(hex_private_key):
    nonce = random.randint(2**10, 2**32)
    checksum = hashlib.sha3_512(str(nonce).encode()).hexdigest()

    private_key = Secp256k1PrivateKey.from_hex(hex_private_key)
    message = private_key.secp256k1_private_key.ecdsa_sign(str(nonce).encode())
    serialized_message = private_key.secp256k1_private_key.ecdsa_serialize(message)
    hex_message = binascii.hexlify(serialized_message)
    return nonce, checksum, hex_message


def verify_nonce(nonce, checksum, message, hex_public_key):
    ##message is hex encoded
    message = binascii.unhexlify(message)
    public_key = Secp256k1PublicKey.from_hex(hex_public_key)
    unserialized = public_key.secp256k1_public_key.ecdsa_deserialize(message)
    result = public_key.secp256k1_public_key.ecdsa_verify(str(nonce).encode(), unserialized)
    return result





def delete_info(asset_list):
    """
    remove sensitive information from the asset key
    private_key, public_key, seriliazed_asset, key, url
    """
    delete = lambda asset_dict: [asset_dict.pop(item) for
        item in ["private_key", "child_key_index", "serialized_asset"]]
    list(map(delete, asset_list))
    return asset_list

def asset_deserialization(asset_state_data):
    asset = asset_pb2.Asset()
    asset.ParseFromString(asset_state_data)
    return MessageToDict(asset, preserving_proto_field_name=True)



def serialize_to_assets(asset_list):
    """
    Given data string stored on the blockchaia, Gets the asset
    from this data by serilizing into it.
    address_dict will be of the form,
    {"public_key": <public_key>, "private_key": <>, "serialized_asset": <serialized data stored on blockchain>,
            "asset_address": <> }
    result:
        {"public_key": <public_key>, "private_key": <>, "asset": asset,
            "asset_address": <> }

    """
    empty_assets, assets = [], []

    for element in asset_list:
        state_data = element["serialized_asset"]
        _asset = asset_deserialization(state_data)
        element.update( _asset)
        is_empty_asset = element.pop("is_empty_asset")
        if is_empty_asset:
            empty_assets.append(element)
        else:
            assets.append(element)
    return empty_assets, assets
