import requests
import json
import binascii
import base64
from pprint import pprint
from faker import Faker
import hashlib
import rethinkdb as ret
import pytz
import datetime
import random
faker = Faker()
command = "`"
import os
REST_API_URL = "172.28.128.4:8008"
GO_API_URL = "172.28.128.1:8001"
import os
import sys

import pymongo
connection = pymongo.MongoClient("172.28.128.1")
db = connection["Testdb"]
user_collection = db["users"]
#user_collection.remove()

nb_dir = os.path.split(os.getcwd())[0]
if nb_dir not in sys.path:
    sys.path.append(nb_dir)
from google.protobuf.json_format import MessageToDict
#from protocompiled import float_account_pb2, account_pb2
from addressing import addresser

from protocompiled import float_account_pb2, account_pb2, asset_pb2, \
                organization_account_pb2, child_account_pb2
from db import accounts_query
import coloredlogs, logging
from errors.errors import ApiBadRequest, ApiInternalError
coloredlogs.install()

NATURE = ["OPEN_TO_OTHERS", "IN_HOUSE", "OPEN_TO_OTHERS_PARTLY"]
OPERATIONS = ["PERMANENT", "SITE", "MOBILE"]


FRESH_START=False
SCOPE = {
    "CALIBERATION": {
        "MECHANICAL": {},
        "ELECTRO_TECHNICAL": {},
        "FLUID_FLOW": {},
        "THERMAL": {},
        "OPTICAL": {},
        "RADIOLOGICAL":{}
    },

    "TESTING": {
        "BIOLOGICAL": {},
        "CHEMICAL":{},
        "ELECTRICAL": {},
        "ELECTRONICS": {},
        "FLUID_FLOW":{},
        "MECHANICAL": {},
        "NON_DESTRUCTIVE": {},
        "PHOTOMETRY": {},
        "RADIOLOGICAL": {},
        "FORENSIC":{}
    },
    "MEDICAL": {
        "MEDICAL":{}
        },
    "PTP": {},
    "RMP": {}


}

DATABASE={
            "ip": "13.232.172.238",
            "port": 28015,
            "secret_table": "secrets",
            "dbname": "main_db",
            "user": "adminuser",
            "password": "VandeMATRAM90990",
            "user_table": "users",
            "public_keys_table": "public_keys"
              }

conn = ret.connect(
        port=DATABASE["port"],
        host=DATABASE["ip"],
        db=DATABASE["dbname"],
        user=DATABASE["user"],
        password=DATABASE["password"])


def revoke_time_stamp(days=0, hours=0, minutes=0):
        tz_kolkata = pytz.timezone('Asia/Kolkata')
        time_format = "%Y-%m-%d %H:%M:%S"
        naive_timestamp = datetime.datetime.now()
        aware_timestamp = tz_kolkata.localize(naive_timestamp)
        ##This actually creates a new instance od datetime with Days and hours
        _future = datetime.timedelta(days=days, hours=hours, minutes=minutes)
        result = aware_timestamp + _future
        return result.timestamp()

def generate_file_like():
        output = StringIO()
        text = []
        for i in range(10):
            text.extend(faker.paragraphs())
        text = " ".join(text)
        output.write(text)
        content = output.getvalue()
        file_hash = hashlib.sha224(content.encode()).hexdigest()
        base64_file_bytes = base64.b64encode(content.encode()).decode()
        return file_hash, base64_file_bytes, faker.file_name()

def gen_gst_number():
    return "".join([random.choice([str(i) for i in range(0, 9)] + [chr(i) for i in range(97, 123)]) for i in range(0, 15)]).upper()

def gen_tan_number():
    return "".join([random.choice([str(i) for i in range(0, 9)] + [chr(i) for i in range(97, 123)]) for i in range(0, 10)]).upper()


def synchronous_deserialize_flt_account(REST_API_URL, address):
        r = requests.get(f"http://{REST_API_URL}/state/{address}")

        if r.json()["data"]:
            acc = float_account_pb2.FloatAccount()
            acc.ParseFromString(base64.b64decode(r.json()["data"]))
            account = MessageToDict(acc, preserving_proto_field_name=True)
        else:
            return False
        return account
        ##decoding data stored on the blockchain

def deserialize_account(REST_API_URL, address):

        r = requests.get(f"http://{REST_API_URL}/state/{address}")
        ##decoding data stored on the blockchain
        if r.json()["data"]:
            acc = organization_account_pb2.OrganizationAccount()
            acc.ParseFromString(base64.b64decode(r.json()["data"]))
            account = MessageToDict(acc, preserving_proto_field_name=True)
        else:
            return False
        return account

def deserialize_child(REST_API_URL, address):

        r = requests.get(f"http://{REST_API_URL}/state/{address}")
        ##decoding data stored on the blockchain
        if r.json()["data"]:
            acc = child_account_pb2.ChildAccount()
            acc.ParseFromString(base64.b64decode(r.json()["data"]))
            account = MessageToDict(acc, preserving_proto_field_name=True)
        else:
            return False
        return account



def get_headers_on_email(email, password):
    r = requests.post("http://localhost:8000/users/login",
                            data=json.dumps({"email": email,
                                "password": password}))
    return {"token": r.json()["authorization"]}


child_one = {'phone_number': '1-813-736-1323',
    'email': 'admin_child_one@qcin.org',
    'password': '(lB&m8Vkov',
    'first_name': 'Child',
    'last_name': 'One'}



child_two = {'phone_number': '908-195-1535x072',
    'email': 'admin_child_two@qcin.org',
    'password': '*$Pl8SRt66',
    'first_name': 'Child',
    'last_name': 'Two'}

master_child = {'phone_number': '1-510-343-7153',
 'email': 'wesleyburton@nabl.org.in',
 'password': 'n8YC4eY4$t',
 'first_name': 'Ashley',
 'last_name': 'Warren'}


master_one = {'pancard': '0-01-123671-X',
    'phone_number': '1-591-892-3234x0550',
    'email': 'child_one@nabl.org.in',
    'role': 'MASTER',
    'password': 'Z9d%lFFN&s',
    'org_name': 'National accredation board of laboratories',
    'gst_number': 'MLOCEGUUVY8SCV2',
    'tan_number': '65CE6OV5WQ'}


master_two = {'pancard': '1-75759-151-6',
    'phone_number': '(207)256-4908x3758',
    'email': 'child_one@fssai.org.in',
    'role': 'MASTER',
    'password': '*sh0UDxsiZ',
    'org_name': 'Food Safety and Standards Authority of India',
    'gst_number': 'FAIJ5KD6VCIUWPV',
    'tan_number': 'QUMJM202M3'}

master_three = {'pancard': '1-05-955167-5',
    'phone_number': '718.977.1898x2146',
    'email': 'child_two@trai.org.in',
    'role': 'MASTER',
    'password': 'B3H3b690!9',
    'org_name': 'Telecom regulatory authority of india',
    'gst_number': 'FVJTH5260QDRN5Q',
    'tan_number': 'J4AZGW3ZPX'}



master_four = {'pancard': '1-05-955167-5',
    'phone_number': '718.977.1898x2146',
    'email': 'child_two@apeda.org.in',
    'role': 'MASTER',
    'password': 'B3H3b690!9',
    'org_name': 'The Agricultural and Processed Food Products Export Development Authority',
    'gst_number': 'FVJTH5260QDRN5Q',
    'tan_number': 'J4AZGW3ZPX'}

master_admin = {'pancard': '0-298-01104-2',
        'phone_number': '1-952-874-4090x6607',
        'email': 'admin_himself@nabcb.org.in',
        'role': 'MASTER',
        'password': 'vGfl9Dau#x',
        'org_name': 'National Accredation Board of Certification Bodies',
        'gst_number': '8LLY8TKQY6FIAMX',
        'tan_number': 'JUQTGKCRIX'}


def db_find_on_key(email):
    try:
        return ret.table("users").filter(ret.row["email"]==email).run(conn).items[0]
    except:
        return False

def db_find_on_key_pending(email):
    try:
        return ret.table("pending_users").filter(ret.row["email"]==email).run(conn).items[0]
    except:
        return False



def create_scope():

    group = random.choice(list(SCOPE.keys()))
    if len(SCOPE[group].keys()) > 2:
       sub_group = random.choice(list(SCOPE[group].keys()))
    elif len(SCOPE[group].keys()) ==  1:
        sub_group = list(SCOPE[group].keys())[0]
    else:
        sub_group = None

    field = faker.catch_phrase()



    nature = random.choice(NATURE)
    operations = random.choice(OPERATIONS)
    description = faker.sentence()
    return {"group": group, "sub_group": sub_group, "field": field, \
            "nature": nature, "operations": operations, "description": description
            }

def register_master(requester, organization):
        headers = get_headers_on_email(requester["email"],
                        requester["password"])

        ##creating account for Master organization
        r = requests.post("http://localhost:8000/accounts/create_organization_account",
                data=json.dumps({"pancard": organization["pancard"],
                    "phone_number": organization["phone_number"],
                    "email": organization["email"],
                    "role": organization["role"],
                    "org_name": organization["org_name"]}), headers=headers)


        if r.json()["error"]:
            logging.info(json.dumps(r.json(), indent = 4))
        else:
            logging.info(json.dumps(r.json()["data"], indent = 4))



def create_asset(email):
    headers = get_headers_on_email(email)
    file_hash, b64_bytes, file_name = generate_file_like()
    expired_on = revoke_time_stamp(days=30, hours=24)

    scope = create_scope()
    logging.info(json.dumps(scope, indent = 4))


    r = requests.post("http://localhost:8000/assets/create_asset",
        data=json.dumps({"file_name": file_name,
                        "file_hash": file_hash,
                        "scope": scope,
                        "base64_file_bytes": b64_bytes,
                        "expired_on": expired_on}), headers=headers)
    data= r.json()["data"]
    logging.info(json.dumps(data, indent = 4))


def get_float_accounts(account):
    headers = get_headers_on_email(account["email"], account["password"])
    r = requests.get("http://localhost:8000/accounts/get_float_accounts",headers=headers)

    logging.info(json.dumps(r.json()["data"], indent=5))



def create_child(account, child_data):
    headers = get_headers_on_email(account["email"], account["password"])
    r = requests.post("http://localhost:8000/accounts/create_child",
                                    data=json.dumps(child_data), headers=headers)
    logging.info(r.json())


def get_children(account):
    ##getting children for the admin account
    r = requests.get("http://localhost:8000/accounts/get_children",
            headers=get_headers_on_email(account["email"], account["password"]))

    logging.info(json.dumps(r.json()["data"], indent=4))




def get_account(account):
    ##getting children for the admin account
    r = requests.get("http://localhost:8000/accounts/get_organization_account",
            headers=get_headers_on_email(account["email"], account["password"]))

    logging.info(json.dumps(r.json()["data"], indent=4))
    return r.json()["data"]

##registering children for the admin, the requests will fail if children already exists



def claim_account(account):
    pending_account = db_find_on_key_pending(account["email"])

    logging.info(pending_account)
    data = {"pancard": pending_account["pancard"],\
                "phone_number": pending_account["phone_number"],
                "email": pending_account["email"], \
                "org_name": pending_account["org_name"],
                "password": account["password"], \
                "tan_number": account["tan_number"],
                "gst_number": account["gst_number"]}
    logging.info(data)
    r = requests.post("http://localhost:8000/accounts/claim_account",
            data=json.dumps(data))
    logging.info(json.dumps(r.json(), indent=5))





admin_password = "1234"
admin_email = "admin@qcin.org"


Admin = ret.table("users").filter(ret.row["email"]==admin_email).run(conn).items[0]
Admin.update({"password": "1234"})



##if master_admin culdnt be found in the pending users table, then create a float_Account transaction
##with admin credentials
if not db_find_on_key_pending(master_admin["email"]):
    logging.info("Master admin couldnt be found in the Database, So registering a master with Admin account")
    register_master(Admin, master_admin)
else:
    logging.info("Master float account created by admin found in the Database")




def get_organization_account(account):
    headers = get_headers_on_email(account["email"], account["password"])
    user = ret.table("users").filter(ret.row["email"] == account["email"]).coerce_to("array").run(conn)[0]
    address = addresser.create_organization_account_address(user["acc_zero_pub"],
                                                index=0)

    r = requests.get("http://localhost:8000/accounts/address",
    params={"address": address})

    logging.info(json.dumps(r.json()["data"], indent = 4))

##check entry of Admin on Blockchain

get_organization_account(Admin)

##creating a child_one with admin
logging.info(f"Creating child with Admin {child_one}")
create_child(Admin, child_one)

logging.info(f"Creating child with Admin {child_two}")
create_child(Admin, child_two)



##getting headers for the child_one
register_master(child_one, master_one)
register_master(child_one, master_two)
register_master(child_two, master_three)
register_master(child_two, master_four)


get_children(Admin)

logging.info("Get all float accounts by the Admin including created by children too")
get_float_accounts(Admin)

##since these float accounts have been registered, lets check whethe the
##admin account on blockchain and its child have right float_Account indexes updated

def upload(issuer, receiver):
    headers = get_headers_on_email(issuer["email"], issuer["password"])

    receiver = db_find_on_key_pending(receiver["email"])
    address= addresser.float_account_address(receiver["parent_pub"],
                            receiver["parent_idx"])

    file_hash, base64_file_bytes, file_name = generate_file_like()
    data = {"file_name": file_name,
            "base64_file_bytes": base64_file_bytes,
             "file_hash": file_hash,
            "scope": create_scope(),
            "expired_on": revoke_time_stamp(days=100, hours=1, minutes=10),
            "address": address}


    r = requests.post("http://localhost:8000/assets/upload",
                                data=json.dumps(data), headers=headers)
    logging.info(json.dumps(r.json(), indent=4))

    if r.json()["error"]:
        logging.info("Since this account has already been claimed")
        logging.info("Trying upload with organization account")
        receiver = db_find_on_key(receiver["email"])

        address= addresser.create_organization_account_address(receiver["acc_zero_pub"],
                            0)
        data.update({"address": address})
        r = requests.post("http://localhost:8000/assets/upload",
                                    data=json.dumps(data), headers=headers)
        logging.info(json.dumps(r.json(), indent=4))

    return r.json()["data"]["issuer_address"], r.json()["data"]["receiver_address"]



def get_assets(account):
    headers = get_headers_on_email(account["email"], account["password"])

    r = requests.get("http://localhost:8000/assets/assets", headers=headers)
    logging.info(json.dumps(r.json()["data"], indent=4))
    return r.json()["data"]

def get_receive_assets(account):
    headers = get_headers_on_email(account["email"], account["password"])

    r = requests.get("http://localhost:8000/assets/receive_assets", headers=headers)
    logging.info(json.dumps(r.json()["data"], indent=4))


##this will create an asset with data for Admin and then creates an empty
## asset for master_admin who stil have a float_account,
##now this asset will betransffered to empty asset


#------------------------------Upload asset ----------------------------------------##
if FRESH_START:
    logging.info(f"Issuing a certificate from admin to the master_one who have a float account{master_one}")
    upload(Admin, master_one)

#------------------------------Get assets for the Admin ----------------------------##


logging.info("Getting all the assets created by Admin")
get_assets(Admin)


#------------------------------Claim account with master one ----------------------------##
logging.info("Now lets claim account with master_one")
claim_account(master_one)
master_one_state = get_account(master_one)
r = requests.get("http://localhost:8000/accounts/address",
    params={"address": master_one_state["float_account_address"]})
logging.info("Checking status of float_account address of master_one, who just have claimed")
logging.info(json.dumps(r.json(), indent=4))



def receive_asset(account):
    logging.info(f"Creating new receive asset for the account {account}")
    headers = get_headers_on_email(account["email"], account["password"])
    data = {
        "_id_": faker.iban(),
        "name": faker.name(),
        "description": faker.paragraph(),
        "at_which_asset_expires": revoke_time_stamp(days=10),
        }

    r = requests.post("http://localhost:8000/assets/create_receive_asset",
                                data=json.dumps(data), headers=headers)
    logging.info(json.dumps(r.json(), indent=4))


logging.info(f"Since we just created receive asset indexes for master_one {master_one}\
            we will check the orgnization account of master_one to see if the receive_asset_idxs of the\
            master_one has been updated or not")


if FRESH_START:
    #------------------------------Receive account for master one -----------------------##
    receive_asset(master_one)

    #-----------------------------Create child for master -----------------------------###

    logging.info(f"Creating child for master_one {master_one} and with child data {master_child} ")
    #create_child(master_one, master_child)

    receive_asset(master_one)


get_organization_account(master_one)
get_receive_assets(master_one)

logging.info("CHeck child account of master_one whether its receive_asset_idxs have been updated or not ")
#get_children(master_one)

#claim_account(master_admin)
#receive_asset(master_admin)
#receive_asset(master_admin)
get_account(master_admin)
get_account(master_one)

def share_asset(account, receive_asset_address, unique_code):

    headers = get_headers_on_email(account["email"], account["password"])
    asset = get_assets(account)[0]
    logging.info(asset)
    asset_address = addresser.create_asset_address(
            asset_id=asset["public"],
            index=asset["idx"]
            )

    logging.info(f"Asset address which will be shared is {asset_address}")
    data = {"revoked_on": revoke_time_stamp(days=30),
            "asset_address": asset_address,
            "receive_asset_address": receive_asset_address,
            "unique_code": unique_code,
            "comments": faker.paragraph()}
    logging.info(f"data for shareasset is {data}")
    r = requests.post("http://localhost:8000/assets/share_asset",
                                data=json.dumps(data), headers=headers)
    logging.info(r.json())

share_asset(master_one, "318c9f07bca8fb08b21659cb1586dcd55114eb5488eeb416a9c927a6662f8da3992917", 11344)
receive_asset(master_one)


"""

issuer_address, receiver_address = upload(Admin, master_admin)

logging.info("Checking issueer asset created by Admin" )
r = requests.get("http://localhost:8000/accounts/address",
    params={"address": issuer_address})
logging.info(json.dumps(r.json(), indent=5))


logging.info("Checking receiver asset created by Admin" )
r = requests.get("http://localhost:8000/accounts/address",
    params={"address": receiver_address})
logging.info(json.dumps(r.json(), indent=5))




##creating a receieve asset with admin account
receive_asset(Admin)


"""
