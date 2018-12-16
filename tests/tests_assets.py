

# Third-party imports...
from nose.tools import assert_true, assert_false, assert_equals
from nose.tools import assert_is_not_none
import requests
from test_static import child_one, child_two, master_admin, master_one, master_two,\
        master_three, master_four, admin, conn, master_three_child_one, \
        master_three_child_two, master_four_child_one, master_four_child_two, \
        master_one_lab_one, master_two_lab_two, master_three_child_one_lab_three,\
        master_three_child_two_lab_four, master_four_child_one_lab_five, \
        master_four_child_two_lab_six
from test_apis import AccountApis, AssetApis
from test_miscelleneous import revoke_time_stamp, create_scope
import json
import addresser
import sys
import os
import coloredlogs, logging
coloredlogs.install()

import rethinkdb as ret
from test_static import d_admin_child_one_master_one
from test_static import d_admin_child_one_master_two
from test_static import d_admin_child_two_master_one
from test_static import d_admin_child_two_master_two
from test_static import d_admin_child_one_master_three_child_one
from test_static import d_admin_child_one_master_four_child_one
from test_static import d_admin_child_two_master_three_child_two
from test_static import d_admin_child_two_master_four_child_two


from test_static import d_master_three_child_one_lab_three
from test_static import d_master_four_child_two_lab_three
from test_static import d_master_three_child_one_lab_four
from test_static import d_master_four_child_two_lab_four
from test_static import d_master_three_child_one_lab_five
from test_static import d_master_four_child_two_lab_five
from test_static import d_master_three_child_one_lab_six
from test_static import d_master_four_child_two_lab_six
from test_static import d_child_two_master_three

file_name = os.path.dirname(os.path.dirname(__file__))
sys.path.append(file_name)
logging.info(file_name)
LAB_SIX_RECEIVE_ASSET = None

RECEIVE_ASSET = None

"""


ASSETS:
    Admin child_one issue certificate d_admin_child_one_master_one  to master_one
    Admin child_one issue certificate d_admin_child_one_master_two  to master_two


    Admin child_two issue certificate d_admin_child_two_master_one  to master_one
    Admin child_two issue certificate d_admin_child_two_master_two  to master_two


    ###Certificates by child one of admin  to children of master_three and master_four
    Admin child_one issue certificate d_admin_child_one_master_three_child_one
            to child_one of master_three

    Admin child_one issue certificate d_admin_child_one_master_three_child_two
            to child_two of master_three


    Admin child_one issue certificate d_admin_child_one_master_four_child_one
            to child_one of master_four


    Admin child_one issue certificate d_admin_child_one_master_four_child_two
            to child_two of master_four




    ###Certificates by child two of admin  to children of master_three and master_four
    Admin child_two issue certificate d_admin_child_two_master_three_child_one
            to child_one of master_three

    Admin child_two issue certificate d_admin_child_two_master_three_child_two
            to child_two of master_three


    Admin child_two issue certificate d_admin_child_two_master_four_child_one
            to child_one of master_four


    Admin child_two issue certificate d_admin_child_two_master_four_child_two
            to child_two of master_four


"""

def db_find_on_key(email):
    try:
        result = ret.table("users").filter(ret.row["email"]==email).run(conn).items[0]
        return result, True
    except Exception as e:
        #logging.error(e)
        return False, False

def db_find_on_key_pending(email):
    try:
        result = ret.table("pending_users").filter(ret.row["email"]==email).run(conn).items[0]
        return result, True
    except Exception as e:
        #logging.error(e)
        return False, False

def db_transfer_assets(issuer_address, receiver_address):
    try:
        result = ret.table("transfer_assets").filter({
            "receiver_address": receiver_address,
            "issuer_address": issuer_address,
            }).run(conn).items[0]
        return result, True
    except Exception as e:
        #logging.error(e)
        return False, False

def db_assets(address):
    try:
        result = ret.table("assets").filter({
            "asset_address": address,
            }).run(conn).items[0]
        return result, True
    except Exception as e:
        #logging.error(e)
        return False, False


def boilerplate_org_registeration(requester, account):
    ##it will try to create a float account, that what means to register
    ## an organization
    response = AccountApis.register_organization(requester, account)
        ##check duplicate entries

    if response == False:
        logging.error(f"The requester <{requester} may have not registered or may be\
            have a float_account which havent been claimed>")

    elif response.status_code == 200:
        logging.info(f"Registering org for the first time {account['org_name']}")
        pending_db_entry, pending_flag = db_find_on_key_pending(account["email"])
        assert_equals(pending_flag, True)
        assert_equals(pending_db_entry["claimed"], False)
        # If the request is sent successfully, then I expect a response to be returned.
        users_db_entry, user_flag = db_find_on_key(account["email"])
        assert_equals(user_flag, False)
        assert_equals(response.status_code, 200)


    elif response.status_code == 400:
        logging.error(response.json())


    else:
        logging.error(f"response is <{response.json()}> and error code {response.status_code}")


    return response

def boilerplate_child_registeration(requester, child):
    response = AccountApis.register_child(requester, child)

    db_entry, user_flag = db_find_on_key(child["email"])
    parent_db_entry, parent_flag = db_find_on_key(requester["email"])

    assert_equals(user_flag, True)
    assert_equals(parent_flag, True)

    ##if requster is a child, check whether the account have child_zero_pub or not
    if response.status_code == 200:
        logging.info(f"Registering child child['first_name'] for the first time for org {requester['org_name']}")
        # If the request is sent successfully, then I expect a response to be returned.
        assert_equals(user_flag, True)
        assert_equals(parent_flag, True)


    elif response.status_code == 400:
        logging.error(response.json())
        assert_equals(user_flag, True)


    else:
        logging.error(f"response is <{response.json()}> and error code {response.status_code}")



def boilerplate_claim_account(requester):
    response = AccountApis.claim_account(requester)


    pending_db_entry, pending_flag = db_find_on_key_pending(requester["email"])
    db_entry, db_flag = db_find_on_key(requester["email"])


    if response.status_code == 200:
        logging.info(f"claiming org {requester['org_name']} for the first time")
        # If the request is sent successfully, then I expect a response to be returned.
        assert_equals(pending_flag, True)
        assert_equals(db_flag, True)
        assert_equals(pending_db_entry["claimed"], True)
        assert_equals(bool(pending_db_entry.get("create_asset_idxs")),
                bool(db_entry.get("create_asset_idxs")))



    elif response.status_code == 400:
        logging.error(response.json())

        assert_equals(pending_flag, True)
        assert_equals(db_flag, True)
        assert_true(pending_db_entry["claimed"])


    else:
        logging.error(f"response is <{response.json()}> and error code {response.status_code}")
    return

def boilerplate_check_children(requester):

    children = AccountApis.get_children(requester)
    account= AccountApis.get_organization_account(requester)

    assert_equals(children.status_code, 200)
    assert_equals(account.status_code, 200)
    logging.info(json.dumps(account.json()["data"], indent=4))

    assert_equals(len(account.json()["data"]["child_account_idxs"]), len(children.json()["data"]))
    assert_equals(account.json()["data"]["child_account_idxs"], [e["parent_idx"] for e in children.json()["data"]])
    return




def boilerplate_issue_aset(requester):
    response = AccountApis.get_float_accounts(requester)
    assert_equals(response.status_code, 200)
    return response.json()["data"]


def boilerplate_upload_asset(requester, account, file_data):
    ##it will try to create a float account, that what means to register
    ## an organization
    logging.info(account)
    pending_db_entry, pending_flag = db_find_on_key_pending(account["email"])
    db_entry, db_flag = db_find_on_key(account["email"])

    if not db_flag and not pending_flag:
        logging.error(f"This account doesnt exists in our database {account}")
        return

    elif db_flag and not pending_flag:
        ##this might be a child account
        if db_entry["role"] == "CHILD":
            logging.info("This is a CHILD acount")
            address = addresser.child_account_address(db_entry["public"], 0)
        else:
            logging.error(f"This account somehow doesnt have a float_account {account}")
            return

    elif pending_flag and not db_flag:
        ##this might be a just float_account
        if not pending_db_entry["claimed"]:
            logging.info("This is a FLOAT acount")

            address = addresser.float_account_address(
                        pending_db_entry["parent_pub"],
                        pending_db_entry["parent_idx"]
            )
    elif pending_flag and db_flag:
        ##this is a account address
        logging.info("This is an ORGANIZATION acount")

        address = addresser.create_organization_account_address(
                    db_entry["acc_zero_pub"],
                    0
        )

    scope = create_scope()
    expired_on = revoke_time_stamp(days=10, minutes=0)

    response = AssetApis.upload_asset(requester, file_data, scope, expired_on, address)
        ##check duplicate entries

    if response == False:
        logging.error(f"The requester <{requester} may have not registered or may be\
            have a float_account which havent been claimed>")

    elif response.status_code == 200:
        issuer_address = response.json()["data"]["issuer_address"]
        receiver_address = response.json()["data"]["receiver_address"]

        transfer_asset, transfer_flag = db_transfer_assets(issuer_address, receiver_address)
        issuer_asset, issuer_flag = db_assets(issuer_address)
        receiver_asset, receiver_flag = db_assets(receiver_address)
        assert_equals(issuer_flag, True)
        assert_equals(receiver_flag, True)
        assert_equals(receiver_flag, True)


    elif response.status_code == 400:
        logging.error(response.json())


    else:
        logging.error(f"response is <{response.json()}> and error code {response.status_code}")


    return response





def boilerplate_create_asset(requester, file_data):
    ##it receives an asset address with the requester and check whether the
    ##thre requester can decrypt the asset or not
    scope = create_scope()
    expired_on = revoke_time_stamp(days=10, minutes=0)

    response = AssetApis.create_asset(requester, file_data, scope, expired_on)
        ##check duplicate entries
    #assert_equals(response.status_code, 200)



def boilerplate_decrypt_keys(requester, address):
    ##it receives an asset address with the requester and check whether the
    ##thre requester can decrypt the asset or not

    response = AssetApis.decrypt_keys(requester, address)
        ##check duplicate entries
    assert_equals(response.status_code, 200)
    logging.info(json.dumps(response.json(), indent=5))


def boilerplate_check_assets(requester):

    assets= AssetApis.get_assets(requester)
    assert_equals(assets.status_code, 200)

    ##now deciphering ownership_received address in the assets transaction on
    ## blockchain
    asset_list = []
    for asset in assets.json()["data"]:
        issuer_asset_address = asset["ownership_received"]
        issuer_asset= AccountApis.get_address(issuer_asset_address)
        assert_equals(issuer_asset.status_code, 200)
        parent_account = AccountApis.get_address(asset["parent_address"])
        assert_equals(parent_account.status_code, 200)
        assert_equals(issuer_asset.status_code, 200)
        asset.update({"ownership_received": issuer_asset.json()["data"],
                    "parent_account": parent_account.json()["data"]
         })

        asset_list.append(asset)
    logging.info(json.dumps(asset_list, indent=5))


def boilerplate_create_receive_asset(requester):
    asset= AssetApis.create_receive_asset(requester)
    assert_equals(asset.status_code, 200)
    logging.info(json.dumps(asset.json(), indent=5))


#############--------------Test Begins----------------------------------------##

def test_upload_admin_child_two_master_three_child_two():
    logging.info("Issue certificate from admin child_two to master_three child_two organization")
    boilerplate_upload_asset(child_two, master_three_child_two, d_admin_child_two_master_three_child_two)


def test_upload_admin_child_two_master_four_child_two():
    logging.info("Issue certificate from admin child_two to master_four child_two organization")
    boilerplate_upload_asset(child_two, master_four_child_two, d_admin_child_two_master_four_child_two)

##child_two of admin issued certificate to child_two of master_three


def test_create_asset_child_two_master_three():
    logging.info("Create certificate by child_two of master_three for himself")


    boilerplate_create_asset(master_three_child_two, d_child_two_master_three)



def test_check_asset_state():
    master_three_assets= AssetApis.get_assets(master_three)


    #assert_equals(master_three_assets.status_code, 200)
    logging.info(json.dumps(master_three_assets.json(), indent=5))


    boilerplate_decrypt_keys(master_three, master_three_assets.json()["data"][1]["address"])
    """
    master_three_child_two_assets= AssetApis.get_assets(master_three_child_two)
    assert_equals(master_three_child_two_assets.status_code, 200)
    logging.info(json.dumps(master_three_child_two_assets.json()["data"], indent=5))

    ##since all the assets of master_three have been created by child_two, data should be same
    assert_equals(master_three_assets.json()["data"], master_three_child_two_assets.json()["data"])



    master_four_assets= AssetApis.get_assets(master_four)
    assert_equals(master_four_assets.status_code, 200)
    logging.info(json.dumps(master_four_assets.json()["data"], indent=5))


    master_four_child_two_assets= AssetApis.get_assets(master_four_child_two)
    assert_equals(master_four_child_two_assets.status_code, 200)
    logging.info(json.dumps(master_four_child_two_assets.json()["data"], indent=5))

    ##since all the assets of master_three have been created by child_two, data should be same
    assert_equals(master_four_assets.json()["data"], master_four_child_two_assets.json()["data"])




    admin_assets= AssetApis.get_assets(admin)
    assert_equals(admin_assets.status_code, 200)
    logging.info(json.dumps(admin_assets.json()["data"], indent=5))


    admin_child_two_assets= AssetApis.get_assets(child_two)
    assert_equals(admin_child_two_assets.status_code, 200)
    logging.info(json.dumps(admin_child_two_assets.json()["data"], indent=5))

    ##since all the assets of master_three have been created by child_two, data should be same
    assert_equals(admin_assets.json()["data"], admin_child_two_assets.json()["data"])
    """
"""

def test_create_receive_asset_admin_child_one():
        account= AccountApis.get_organization_account(admin)
        logging.info(json.dumps(account.json()["data"], indent=5))

        if not account.json()["data"].get("receive_asset_idxs"):
            logging.info("Create receive asset idxs empty")
            boilerplate_create_receive_asset(child_one)

        account= AccountApis.get_organization_account(admin)
        logging.info(json.dumps(account.json()["data"], indent=5))

        admin_db = ret.table("users").filter({"email": admin["email"]}).coerce_to("array").run(conn)[0]
        child_one_db = ret.table("users").filter({"email": child_one["email"]}).coerce_to("array").run(conn)[0]
        assert_equals(child_one_db.get("receive_asset_idxs"), admin_db.get("receive_asset_idxs"))

        receive_asset = ret.table("receive_assets")\
            .filter({"idx": child_one_db.get("receive_asset_idxs")[0]})\
            .coerce_to("array")\
            .run(conn)[0]
        logging.info(json.dumps(receive_asset, indent=5))

        ##since this reciev_Asset was created by child, its child_zero_pub must
        ##be equal to public of child account
        child_account= AccountApis.get_organization_account(child_one)
        logging.info(json.dumps(child_account.json()["data"], indent=5))

        assert_equals(child_account.json()["data"]["public"], receive_asset["child_zero_pub"])

        ##the receive asset of child_one account blockchain must match
        assert_equals(child_account.json()["data"].get("receive_asset_idxs"),
                account.json()["data"].get("receive_asset_idxs"))

        ##fetchinf receive asset from the blockchain
        receive_asset = AssetApis.get_receive_assets(admin)
        logging.info(json.dumps(receive_asset.json()["data"], indent=5))


        global RECEIVE_ASSET
        RECEIVE_ASSET = receive_asset.json()["data"][0]

## share  asset, master_three_child_two and master_four_child_two will share their
## certificates with admin_child_one,
def test_share_certificate_master_three_child_two_to_admin_child_one():
        master_three_child_two_assets= AssetApis.get_assets(master_three_child_two)
        asset = master_three_child_two_assets.json()["data"][0]
        logging.info(json.dumps(asset, indent=5))
        share_asset = AssetApis.create_share_asset(master_three_child_two,
                        asset["address"], RECEIVE_ASSET.get("address"),
                                RECEIVE_ASSET.get("unique_code"))
        logging.info(f"This is the SHARE_ASSET {share_asset.json()}")

        assert_equals(share_asset.status_code, 200)
        logging.info(json.dumps(share_asset.json()["data"], indent=10))


def test_upload_admin_child_one_master_two():
    logging.info("Issue certificate from admin child_one to master_two organization")
    boilerplate_upload_asset(child_one, master_two, d_admin_child_one_master_two)

def test_upload_admin_child_one_master_one():
    logging.info("Issue certificate from admin child_one to master_one organization")
    boilerplate_upload_asset(child_one, master_one, d_admin_child_one_master_one)



def test_upload_admin_child_two_master_one():
    logging.info("Issue certificate from admin child_two to master_one organization")
    boilerplate_upload_asset(child_two, master_one, d_admin_child_two_master_one)


def test_claim_master_two_account():
    boilerplate_claim_account(master_two)

def test_create_receive_asset_master_four_child_one():
        boilerplate_create_receive_asset(master_four_child_one)

def test_create_receive_asset_master_four():
        boilerplate_create_receive_asset(master_four)


def test_create_receive_asset_master_four_child_two():
        boilerplate_create_receive_asset(master_four_child_two)



def test_check_account_child_one_master_four():
    ##Till now, child_one of master_four have created an asset
    ##master_four himself has created an receive_asset
    ## child_two of master_four has created an receive_asset
    account= AccountApis.get_organization_account(master_four)
    assert_equals(account.status_code, 200)
    logging.info(json.dumps(account.json()["data"], indent=5))

    master_four_db = ret.table("users").filter(ret.row["email"]==master_four["email"]).run(conn).items[0]

    assert_equals(account.json()["data"]["receive_asset_idxs"],
            master_four_db["receive_asset_idxs"])


    ##checking account of the parent i.e master_four
    account= AccountApis.get_organization_account(master_four_child_one)
    assert_equals(account.status_code, 200)
    logging.info(json.dumps(account.json()["data"], indent=5))
    child_one_db = ret.table("users").\
                filter(ret.row["email"]==master_four_child_one["email"])\
                .run(conn).items[0]

    assert_equals(account.json()["data"]["receive_asset_idxs"],
            child_one_db["receive_asset_idxs"])


    ##checking account of master_four child_two
    account= AccountApis.get_organization_account(master_four_child_two)
    assert_equals(account.status_code, 200)
    logging.info(json.dumps(account.json()["data"], indent=5))
    child_two_db = ret.table("users").\
                filter(ret.row["email"]==master_four_child_two["email"])\
                .run(conn).items[0]

    assert_equals(account.json()["data"]["receive_asset_idxs"],
            child_two_db["receive_asset_idxs"])



    receive_assets = AssetApis.get_receive_assets(master_four_child_two)
    assert_equals(receive_assets.status_code, 200)
    logging.info(json.dumps(receive_assets.json()["data"], indent=5))


    receive_assets = AssetApis.get_receive_assets(master_four)
    assert_equals(receive_assets.status_code, 200)
    logging.info(json.dumps(receive_assets.json()["data"], indent=5))



    global LAB_SIX_RECEIVE_ASSET
    LAB_SIX_RECEIVE_ASSET = receive_assets.json()["data"][0]






def test_upload_admin_child_two_master_two():
    logging.info("Issue certificate from admin child_two to master_two organization")
    boilerplate_upload_asset(child_two, master_two, d_admin_child_two_master_two)
##till now we have achieved following tasks,
## admin child_one issued two certifcates, one to master_one and other to master_two
##admin child_two have also issued two certificates, one to master_one and other
## to master_two

##Check 1
##since master_two havent claimed its account, so it shoulnt be able to login
def test_failed_login_from_float_account_master_two():
    logging.info(f"master_two shouldnt be able to login since it hasnt claimed its accuont{master_two}")
    master2= AccountApis.get_organization_account(master_two)
    #assert_equals(master2.status_code, 500)

##now lets claim master_two account, and ideally master_two float_account must have
##two entries in create_float_idxs which must be passed on to its orgnization_account




##now lets check orgnization account of master_two to see, if creat_Asset_idxs array has
###two entries in it
def test_check_account_master_two():
    master2= AccountApis.get_organization_account(master_two)
    assert_equals(master2.status_code, 200)

    master2_float_account= AccountApis.get_address(master2.json()["data"]["float_account_address"])
    logging.info(master2_float_account)
    logging.info(json.dumps(master2_float_account.json(), indent=5))

    assert_equals(master2_float_account.status_code, 200)

    #assert_equals(master2.json()["data"]["create_asset_idxs"], 200)
    assert_equals(master2_float_account.json()["data"]["create_asset_idxs"], \
            master2.json()["data"]["create_asset_idxs"])

    #logging.info(json.dumps(master2.json(), indent=5))
    #logging.info(json.dumps(master2_float_account.json(), indent=5))


##Check assets issued by child_one and child_two of admin to the master_one
def test_check_assets_master_one():
    assets= AssetApis.get_assets(master_one)
    assert_equals(assets.status_code, 200)
    logging.info(json.dumps(assets.json()["data"], indent=5))

    ##now deciphering ownership_received address in the assets transaction on
    ## blockchain
    asset_list = []
    for asset in assets.json()["data"]:
        issuer_asset_address = asset["ownership_received"]
        issuer_asset= AccountApis.get_address(issuer_asset_address)
        parent_account = AccountApis.get_address(asset["parent_address"])
        assert_equals(parent_account.status_code, 200)
        logging.info(parent_account)
        assert_equals(issuer_asset.status_code, 200)
        asset.update({"ownership_received": issuer_asset.json()["data"],
                    "parent_account": parent_account.json()["data"]
         })
        asset_list.append(asset)
    logging.info(json.dumps(asset_list, indent=5))


def test_upload_admin_child_one_master_three_child_one():
    logging.info("Issue certificate from admin child_one to master_three child_one organization")
    boilerplate_upload_asset(child_one, master_three_child_one, d_admin_child_one_master_three_child_one)


def test_upload_admin_child_one_master_four_child_one():
    logging.info("Issue certificate from admin child_one to master_four child_one organization")
    boilerplate_upload_asset(child_one, master_four_child_one, d_admin_child_one_master_four_child_one)

def test_upload_admin_child_two_master_three_child_two():
    logging.info("Issue certificate from admin child_two to master_three child_two organization")
    boilerplate_upload_asset(child_two, master_three_child_two, d_admin_child_two_master_three_child_two)


def test_upload_admin_child_two_master_four_child_two():
    logging.info("Issue certificate from admin child_two to master_four child_two organization")
    boilerplate_upload_asset(child_two, master_four_child_two, d_admin_child_two_master_four_child_two)





from test_static import d_master_three_child_one_lab_three
from test_static import d_master_four_child_two_lab_three
from test_static import d_master_three_child_one_lab_four
from test_static import d_master_four_child_two_lab_four

from test_static import d_master_three_child_one_lab_five
from test_static import d_master_four_child_two_lab_five
from test_static import d_master_three_child_one_lab_six
from test_static import d_master_four_child_two_lab_six



##lab three
def test_d_master_three_child_one_lab_three():
    logging.info("Issue certificate from child_one of master_three to lab_three organization")
    boilerplate_upload_asset(master_three_child_one, master_three_child_one_lab_three, d_master_three_child_one_lab_three)

def test_d_master_four_child_two_lab_three():
    logging.info("Issue certificate from child_two of master_four to lab_three organization")
    boilerplate_upload_asset(master_four_child_two, master_three_child_one_lab_three, d_master_four_child_two_lab_three )


##lab four

def test_d_master_three_child_one_lab_four():
    logging.info("Issue certificate from child_one of master_three to lab_four organization")
    boilerplate_upload_asset(master_three_child_one, master_three_child_two_lab_four, d_master_three_child_one_lab_four )



def test_d_master_four_child_two_lab_four():
    logging.info("Issue certificate from child_two of master_four to lab_four organization")
    boilerplate_upload_asset(master_four_child_two, master_three_child_two_lab_four, d_master_four_child_two_lab_four)


##lab five


def test_d_master_three_child_one_lab_five():
    logging.info("Issue certificate from child_one of master_three to lab_five organization")
    boilerplate_upload_asset(master_three_child_one, master_four_child_one_lab_five, d_master_three_child_one_lab_five)



def test_d_master_four_child_two_lab_five():
    logging.info("Issue certificate from child_two of master_four to lab_five organization")
    boilerplate_upload_asset(master_four_child_two, master_four_child_one_lab_five, d_master_four_child_two_lab_five)

##lab six

def test_d_master_three_child_one_lab_six():
    logging.info("Issue certificate from child_one of master_three to lab_six organization")
    boilerplate_upload_asset(master_three_child_one, master_four_child_two_lab_six, d_master_three_child_one_lab_six)



def test_d_master_four_child_two_lab_five():
    logging.info("Issue certificate from child_two of master_four to lab_six organization")
    boilerplate_upload_asset(master_four_child_two, master_four_child_two_lab_six, d_master_four_child_two_lab_six)


##check lab assets

def test_lab_six_assets():
    boilerplate_check_assets(master_four_child_two_lab_six)


##create receive assets for lab six

def test_create_receive_asset_lab_six():
        boilerplate_create_receive_asset(master_four_child_two_lab_six)

##ONLY lab three and lab SIX have claimed their accounts

def test_check_account_lab_six():
    account= AccountApis.get_organization_account(master_four_child_two_lab_six)
    assert_equals(account.status_code, 200)
    logging.info(json.dumps(account.json()["data"], indent=5))

    receive_assets = AssetApis.get_receive_assets(master_four_child_two_lab_six)
    assert_equals(receive_assets.status_code, 200)
    logging.info(json.dumps(receive_assets.json()["data"], indent=5))
    global LAB_SIX_RECEIVE_ASSET
    LAB_SIX_RECEIVE_ASSET = receive_assets.json()["data"][0]




def test_check_assets_lab_five():
    assets= AssetApis.get_assets(master_four_child_one_lab_five)
    assert_equals(assets.status_code, 401)
    #logging.info(json.dumps(assets.json()["data"], indent=5))
    logging.info("Lab five havent claimed its account, so shouldnt be able to fetch the assets assigned to it")



def test_check_assets_lab_four():
    assets= AssetApis.get_assets(master_three_child_two_lab_four)
    assert_equals(assets.status_code, 401)
    logging.info("Lab four havent claimed its account, so shouldnt be able to fetch the assets assigned to it")

##Check assets issued by child_one and child_two of admin to the master_one
def test_check_assets_lab_three():
    logging.info("Checking assets of Lab three")
    assets= AssetApis.get_assets(master_three_child_one_lab_three)
    assert_equals(assets.status_code, 200)
    logging.info(json.dumps(assets.json()["data"], indent=5))


def test_share_asset_lab_three_with_lab_six():
    logging.info(f"Lab three have a certificate {d_master_three_child_one_lab_three} which \
            has been issued by child_one of master three, this ceritifcate willbe shared\
            with lab six receive asset")
    logging.info("Checking assets of Lab three")
    assets= AssetApis.get_assets(master_three_child_one_lab_three)
    assert_equals(assets.status_code, 200)
    asset_address = assets.json()["data"][0].get("address")
    logging.info(f"This is the asset_address of lab three which will be shared {asset_address}")
    logging.info(f"Here is the receive asset addrress {LAB_SIX_RECEIVE_ASSET.get("address")}\
            and unique code {LAB_SIX_RECEIVE_ASSET.get("unique_code")}")


    share_asset = AssetApis.create_share_asset(master_three_child_one_lab_three,
                    asset_address, LAB_SIX_RECEIVE_ASSET.get("address"),
                            LAB_SIX_RECEIVE_ASSET.get("unique_code"))
    assert_equals(share_asset.status_code, 200)
    logging.info(share_asset.json()["data"])\

def test_check_share_assets_lab_three():
    account= AccountApis.get_organization_account(master_three_child_one_lab_three)
    logging.info(json.dumps(account.json()["data"], indent=5))

    account= AssetApis.get_assets(master_three_child_one_lab_three)
    logging.info(json.dumps(account.json()["data"], indent=5))


    #assets= AssetApis.get_share_assets(master_three_child_one_lab_three)
    #assert_equals(assets.status_code, 401)
    #logging.info(json.dumps(assets.json()["data"], indent=5))
    #logging.info("Lab five havent claimed its account, so shouldnt be able to fetch the assets assigned to it")



def test_admin_account():
    account= AccountApis.get_organization_account(admin)
    assert_equals(account.status_code, 200)

    children = AccountApis.get_children(admin)
    assert_equals(children.status_code, 200)

    logging.info(json.dumps(account.json(), indent=5))
    logging.info(json.dumps(children.json(), indent=5))

    master1= AccountApis.get_organization_account(master_one)
    assert_equals(master1.status_code, 200)

    #master2= AccountApis.get_organization_account(master_two)
    #assert_equals(master2.status_code, 200)

    logging.info(json.dumps(master1.json(), indent=5))
    #logging.info(json.dumps(master2.json(), indent=5))
"""
