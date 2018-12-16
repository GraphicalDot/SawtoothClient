

```python
import requests
import json
import binascii
import base64
from faker import Faker
import hashlib
import rethinkdb as ret
import pytz
import datetime
from io import StringIO
faker = Faker()
command = "`"
import os
REST_API_URL = "172.28.128.3:8008"
import os
import sys
nb_dir = os.path.split(os.getcwd())[0]
if nb_dir not in sys.path:
    sys.path.append(nb_dir)
from addressing import addresser
from google.protobuf.json_format import MessageToDict
from protocompiled import float_account_pb2, account_pb2


#Organization account will be created for every  organization and it must be claimed
##by the admin of the organization.
## after that an organization can create a child account directly without floating
## a float_account.

## an organization can make a child account deactive based on their perogative

## if a child is going to register a new account, a child will generate a
## a random index on the flt_acc_idxs array

## If a child is to create a new asset it weill generate a new idxs on the parent
##organization create_asset_idxs

## when organization admin claims a its float_account a new child account
##will be created automatically and all the asset which has been given to the
## organization will then be transffered to the his default child account



##ideally, An organizatin admin should be able to do everything what a child
## can do, so  an organization can receive certificates from others,
## receive a share asset ransaction etc  


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
        file_hash = hashlib.sha3_224(content.encode()).hexdigest()
        base64_file_bytes = base64.b64encode(content.encode()).decode()
        return file_hash, base64_file_bytes, faker.file_name()
```


```python
##if you want to start from scratch, make sure you have deleted all the tables from the main_db

#for table in ret.table_list().run(conn):
#    ret.table(table).delete().run(conn)


##When app starts a new accunt corresponding to ADMIN will be inserted into the users_table in main_db (rethinkdb)
##The details are as follows
##THe default password for Admin is "1234" as specified in the config file, if you want to change this default
##change it in the config file, delete Admin from user_table and start the app again.
Admin = ret.table("users").run(conn).items[0]
Admin
```




    {'acc_mstr_pub': None,
     'acc_zero_pub': '0326ff3a43ddfa356c3a000f3d185d41ef8747dca6896e2f91f5bc39e06547b481',
     'admin_zero_pub': None,
     'child_acc_idxs': [],
     'claimed': True,
     'claimed_on': None,
     'closed': False,
     'create_asset_idxs': [],
     'email': 'admin@qcin.org',
     'encrypted_admin_mnemonic': None,
     'encrypted_mnemonic': None,
     'flt_acc_idxs': [],
     'id': '17671104-a2b8-4e64-8198-ebcf0f801747',
     'pancard': None,
     'parent_idx': 0,
     'parent_pub': None,
     'password': '$2b$12$n8RQ0XK7/Ho8EZklBIpHDeFPD/AYTOE/EadNCYrWmBqPv5KwsYPnm',
     'phone_number': None,
     'recvd_asset_idxs': [],
     'role': 'ADMIN',
     'salt': None,
     'share_asset_idxs': [],
     'user_id': 'd4ede85e-ddc0-4e14-9731-ef66af3be381'}




```python
##log with the Admin and get the headers required for making any requests
r = requests.post("http://localhost:8000/users/login", data=json.dumps({"email": Admin["email"] , "password": "1234" }))
headers =  {"token": r.json()["authorization"]}
headers
```




    {'token': 'eyJhbGciOiJIUzI1NiIsImlhdCI6MTU0MDg4OTMzNywiZXhwIjoxNTQwODkyOTM3fQ.eyJlbWFpbCI6ImFkbWluQHFjaW4ub3JnIiwicHVibGljX2tleSI6IjAzMjZmZjNhNDNkZGZhMzU2YzNhMDAwZjNkMTg1ZDQxZWY4NzQ3ZGNhNjg5NmUyZjkxZjViYzM5ZTA2NTQ3YjQ4MSJ9.b0YUP5qzMBuhHxvhwpa2VbdbCUmDvYqBsimVjcb9AnQ'}




```python
##Generating random data for Master organization,
Masterdata = {"pancard": faker.isbn10(), "phone_number": faker.phone_number(), "email": faker.email(), "user_role": "MASTER", "first_name": faker.first_name(), \
              "last_name": faker.last_name(), "password": faker.password(), "organization_name": faker.company(), "adhaar": faker.iban()}
```


```python
##creating account for Master organization
r = requests.post("http://localhost:8000/accounts/create_account", data=json.dumps({"pancard": Masterdata["pancard"], "phone_number": Masterdata["phone_number"], "email"
Masterdata["email"], "user_role": Masterdata["user_role"]}), headers=headers)
r.json()
```


```python
##checking if the data entered into the pending_users table is correct or not
user = ret.table("pending_users").run(conn).items[0]
if user["email"] != Masterdata["email"]:
    raise Exception("Entries in database for the master organization doesnt match")

if not user["claimed"]:
    raise Exception("The pending user havent claimed his account yet, This is a huge error")
```


    ---------------------------------------------------------------------------

    Exception                                 Traceback (most recent call last)

    <ipython-input-18-590b8133e2b2> in <module>()
          2 user = ret.table("pending_users").run(conn).items[0]
          3 if user["email"] != Masterdata["email"]:
    ----> 4     raise Exception("Entries in database for the master organization doesnt match")
          5
          6 if not user["claimed"]:


    Exception: Entries in database for the master organization doesnt match



```python
##ideally the user who havent claimed his account shouldnt be able to create more acocunts
r = requests.post("http://localhost:8000/users/login", data=json.dumps({"email": Masterdata["email"] , "password": Masterdata["password"] }))
if not r.json()["error"]:
    raise Exception("Since Master havent claimed his account, He shouldnt be able to login into the account")
```


```python
##Claiming Master account now, This will be done after verifying their email, phone number, pancard or adhaar
r = requests.post("http://localhost:8000/accounts/claim_account", data=json.dumps({"pancard": Masterdata["pancard"],\
    "phone_number": Masterdata["phone_number"], "email": Masterdata["email"], \
   "organization_name": Masterdata["organization_name"],  "password": Masterdata["password"], \
 "first_name": Masterdata["first_name"], "last_name": Masterdata["last_name"], "adhaar": Masterdata["adhaar"]}))
r.json()
```




    {'message': 'The user doenst have corresponding float account',
     'error': True,
     'success': False}



###### Now check if the Master account has been claimed in the pending users or not and if the Master is now present in the users table or not


```python
#checking in the pending users table for the data of Master
result = ret.table("pending_users").filter(ret.row["email"]==Masterdata["email"]).run(conn).items[0]
if not result:
    raise Exception("User must be present in the pending_users table")

if not result["claimed"]:
    raise Exception("The account should be claimed by now, It has been claimed")
```


    ---------------------------------------------------------------------------

    IndexError                                Traceback (most recent call last)

    <ipython-input-26-4ae389f95b87> in <module>()
          1 #checking in the pending users table for the data of Master
    ----> 2 ret.table("pending_users").filter(ret.row["email"]==Masterdata["email"]).run(conn).items[0]


    IndexError: deque index out of range


###### Now check if the Admin float account index matched with the entry in users_table for the Master


```python
Master_DB = ret.table("users").filter(ret.row["email"]==Masterdata["email"]).run(conn).items[0]
Admin = ret.table("users").filter(ret.row["email"]==Admin["email"]).run(conn).items[0]
if not Admin["flt_acc_idxs"][0] == Master_DB["parent_idx"]:
    raise Excpetion("The parent_idx in Master should match with the only key present in the float_account_idxs in Admin")
```


    ---------------------------------------------------------------------------

    IndexError                                Traceback (most recent call last)

    <ipython-input-27-3f9ba0604b64> in <module>()
    ----> 1 Master_DB = ret.table("users").filter(ret.row["email"]==Masterdata["email"]).run(conn).items[0]
          2 Admin


    IndexError: deque index out of range



```python
##now login with Master
r = requests.post("http://localhost:8000/users/login", data=json.dumps({"email": Masterdata["email"] , "password": Masterdata["password"] }))
headers =  {"token": r.json()["authorization"]}
```

###### Generating random data for LAB, Master can create accounts for LAB.


```python
Labdata = {"pancard": faker.isbn10(), "phone_number": faker.phone_number(), "email": faker.email(), "user_role": "LAB", "first_name": faker.first_name(), \
     ...:          "last_name": faker.last_name(), "password": faker.password(), "organization_name": faker.company(), "adhaar": faker.iban()}
```


```python
Labdata
```




    {'pancard': '1-4593-8104-1',
     'phone_number': '846-465-8512',
     'email': 'kvaughn@mckinney.com',
     'user_role': 'LAB',
     'first_name': 'Linda',
     'last_name': 'Espinoza',
     'password': '_Xf75AtNe8',
     'organization_name': 'Solis-Baker',
     'adhaar': 'GB57KUDZ5000674592852'}




```python
r = requests.post("http://localhost:8000/accounts/create_account", data=json.dumps({"pancard": Labdata["pancard"], "phone_number": Labdata["phone_number"], "email": Lab
     data["email"], "user_role": Labdata["user_role"]}), headers=headers)
```


```python
##check if the lab is now present in the pending users table or not
Lab_DB = ret.table("pending_users").filter(ret.row["email"]==Labdata["email"]).run(conn).items[0]
if not Lab_DB:
    raise Exception("Labdata is not present in the pneding_users table")

##check if parent_pub in Lab_DB is equal to the Master_DB acc_zero_pub
if not Lab_DB["parent_zero_pub"] == Master_DB["acc_zero_pub"]:
    raise Exception("Since Master created Lab, Lab parent_zero_pub must match with master acc_zero_pub")
```

###### Now Master will issue certificate to Lab
The process is as follows,
1. Master will generate a random index at the create_asset_idx array and float a create_asset transaction on the blockchain
2. Lab will also generate a random index at the create_asset_idxs array and will float an empty create_asset transaction on the the blockchain.
3. We both now have a create_asset address by the Master and the create_asset address for the asset creted by the Lab, Now a third transaction will be float called as Tansfer asset which will have input as the issuer_address (Master in this case)  and the receiver_address(Lab in this case).


```python
#Generate a file like object
file_hash, base64_file_bytes, file_name = generate_file_like()
```


```python
r = requests.post("http://localhost:8000/upload/certupload", data=json.dumps({"usr_pancard": labdata["pancard"], "usr_phone_number": labdata["phone_number"], "usr_email
     ...: ": labdata["email"], "file_name": file_name, "file_hash": file_hash, "base64_file_bytes": base64_file_bytes, "scope": {}, "usr_role": "LAB", "expired_on": expired_on}),
     ...:  headers=headers)
```


```python
##This api is for transffering certificate which lies with issuer_address to receiver_address
r = requests.post("http://localhost:8000/upload/cert_transfer", data=json.dumps({"issuer_address": issuer_address, "receiver_address": receiver_address, "expired_on": e
     ...: xpired_on }), headers=headers)
```
