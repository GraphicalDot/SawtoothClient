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
# -----------------------------------------------------------------------------

import enum
import hashlib
import binascii
import coloredlogs, logging
coloredlogs.install()

FAMILY_NAME = 'remedium_healthcare'


NS = hashlib.sha512(FAMILY_NAME.encode()).hexdigest()[:6]


class AssetSpace(enum.IntEnum):
    START = 1
    STOP =  64


class ShareAssetSpace(enum.IntEnum):
    START = 65
    STOP =  128


class ReceiveAssetSpace(enum.IntEnum):
    START =  129
    STOP =  192


class TransferAssetSpace(enum.IntEnum):
    START =  193
    STOP =  256


class SharedSecretSpace(enum.IntEnum):
    START = 256
    STOP = 320

class UserAccountSpace(enum.IntEnum):
    START = 321
    STOP = 384


class OrganizationAccountSpace(enum.IntEnum):
    START = 385
    STOP = 448

class ChildAccountSpace(enum.IntEnum):
    START = 449
    STOP = 512

class ReceiveSecretSpace(enum.IntEnum):
    START = 513
    STOP = 576


def address_is(address):

    if address[:len(NS)] != NS:
        print ("THis is other family")
        return AddressSpace.OTHER_FAMILY, None

    infix = int(address[14:17], 16)
    int_hex = address[6:14]


    if _contains(infix, AssetSpace):
        result = AddressSpace.CREATE_ASSET

    elif _contains(infix, ShareAssetSpace):
        result = AddressSpace.SHARE_ASSET

    elif _contains(infix, ReceiveAssetSpace):
        result = AddressSpace.RECEIVE_ASSET

    elif _contains(infix, SharedSecretSpace):
        result = AddressSpace.SHARED_SECRET

    elif _contains(infix, UserAccountSpace):
        result = AddressSpace.USER_ACCOUNT


    elif _contains(infix, OrganizationAccountSpace):
        result = AddressSpace.ORGANIZATION_ACCOUNT

    elif _contains(infix, ChildAccountSpace):
        result = AddressSpace.CHILD_ACCOUNT


    elif _contains(infix, TransferAssetSpace):
        result = AddressSpace.TRANSFER_ASSET


    elif _contains(infix, ReceiveSecretSpace):
        result = AddressSpace.RECEIVE_SECRET

    else:
        result = AddressSpace.OTHER_FAMILY


    return (result.name, hex_to_int(int_hex))

def is_account_address(address):
    result = address_is(address)
    if result[0] != "CREATE_ACCOUNT":
        return False
    return True





@enum.unique
class AddressSpace(enum.IntEnum):
    CREATE_ASSET = 0
    SHARE_ASSET = 1
    RECEIVE_ASSET = 2
    TRANSFER_ASSET = 3
    SHARED_SECRET = 4
    RECEIVE_SECRET =5
    USER_ACCOUNT = 6
    ORGANIZATION_ACCOUNT=7
    CHILD_ACCOUNT=8
    OTHER_FAMILY = 100




def shared_secret_address(public, index):

    index_hex = '{:08x}'.format(index)
    full_hash = _hash(public)


    return NS \
            + index_hex\
            +_compress(full_hash, SharedSecretSpace.START, SharedSecretSpace.STOP)\
            + full_hash[:53]

def receive_secret_address(public, index):

    index_hex = '{:08x}'.format(index)
    full_hash = _hash(public)


    return NS \
            + index_hex\
            +_compress(full_hash, ReceiveSecretSpace.START, ReceiveSecretSpace.STOP)\
            + full_hash[:53]




def user_address(public, index):
    index_hex = '{:08x}'.format(index)
    full_hash = _hash(public)
    return NS \
            + index_hex\
            +_compress(full_hash, UserAccountSpace.START, \
                    UserAccountSpace.STOP)\
            + full_hash[:53]



def organization_address(public, index):
    index_hex = '{:08x}'.format(index)
    full_hash = _hash(public)
    return NS \
            + index_hex\
            +_compress(full_hash, OrganizationAccountSpace.START, \
                        OrganizationAccountSpace.STOP)\
            + full_hash[:53]


def child_address(public, index):
    index_hex = '{:08x}'.format(index)
    full_hash = _hash(public)
    return NS \
            + index_hex\
            +_compress(full_hash, ChildAccountSpace.START, \
                        ChildAccountSpace.STOP)\
            + full_hash[:53]

def asset_address(public, index):
    index_hex = '{:08x}'.format(index)
    full_hash = _hash(public)
    return NS \
            + index_hex\
            +_compress(full_hash, AssetSpace.START, AssetSpace.STOP)\
            + full_hash[:53]




def share_asset_address(public,  index):
    index_hex = '{:08x}'.format(index)
    full_hash = _hash(public)
    return NS \
            + index_hex\
            +_compress(full_hash, ShareAssetSpace.START, ShareAssetSpace.STOP)\
            + full_hash[:53]



def transfer_asset_address(public,  index):
    index_hex = '{:08x}'.format(index)
    full_hash = _hash(public)
    return NS \
            + index_hex\
            +_compress(full_hash, TransferAssetSpace.START, TransferAssetSpace.STOP)\
            + full_hash[:53]


def receive_asset_address(public, index):
    index_hex = '{:08x}'.format(index)
    full_hash = _hash(public)
    return NS \
            + index_hex\
            +_compress(full_hash, ReceiveAssetSpace.START, ReceiveAssetSpace.STOP)\
            + full_hash[:53]



def _hash(identifier):
    return hashlib.sha512(hashlib.sha512(identifier.encode()).hexdigest().encode()).hexdigest()


def _compress(address, start, stop):
    ##This calculates the mod of the address with (stop-start)+start,
    ##The benefit being
    return "%.3X".lower() % (int(address, base=16) % (stop - start) + start)




def _contains(num, space):
    return space.START <= num < space.STOP

def hex_to_int(int_hex):
    return int.from_bytes(binascii.unhexlify(int_hex), byteorder='big')



def test_address(key):
    g = random.randint(0, 2**32-1)
    _share_secret_address = shared_secret_address(key, g)
    _receive_secret_address = receive_secret_address(key, g)
    _asset_address = asset_address(key, g)
    _share_asset_address = share_asset_address(key, g)
    _receive_asset_address = receive_asset_address(key, g)
    _transfer_asset_address = transfer_asset_address(key, g)

    user_account_address = user_address(key, g)
    organization_acc_address = organization_address(key, g)
    child_acc_address = child_address(key, g)

    print ("SHARE_SECRET", _share_secret_address, address_is(_share_secret_address))
    print ("RECEIVE_SECRET", _receive_secret_address, address_is(_receive_secret_address))
    print ("USER_ACCOUNT", user_account_address, address_is(user_account_address))
    print ("Organization Address", organization_acc_address, address_is(organization_acc_address))
    print ("Child account Address", child_acc_address, address_is(child_acc_address))

    print ("Create Asset Address", _asset_address, address_is(_asset_address))
    print ("Share asset address", _share_asset_address, address_is(_share_asset_address))
    print ("Receiver asset address", _receive_asset_address, address_is(_receive_asset_address))
    print ("Transfer assset address", _transfer_asset_address, address_is(_transfer_asset_address) )
