

# Third-party imports...
from nose.tools import assert_true, assert_false, assert_equals
from nose.tools import assert_is_not_none
import requests
from test_static import child_one, child_two, master_admin, master_one, master_two,\
        master_three, master_four, admin, conn, master_three_child_one, \
        master_three_child_two, master_four_child_one, master_four_child_two, \
        master_one_lab_one, master_two_lab_two, master_three_child_one_lab_three,\
        master_three_child_two_lab_four, master_four_child_one_lab_five, \
        master_four_child_two_lab_six, user_one
from test_apis import AccountApis
instance = AccountApis()
import json
import coloredlogs, logging
coloredlogs.install()

FRESH_START= False

import rethinkdb as ret

"""
Admin is already present on the blockchain
Admin will register two children of himself/herself.
    child_one
    child_two

    Admin will register master_admin Master orgnization
    Admin child_one will register master_one Master organization
    Admin child_one will register master_two Master organization
    Admin child_two will register master_three Master organization
    Admin child_two will register master_four Master organization

    MASTERS:
        master_one will claim its account
        master_three will claim its account
        master_four will claim its account

            master_three will create two children
                master_three_child_one
                master_three_child_two

            master_four will created its own two children
                master_four_child_one
                master_four_child_two

                LABS:
                    master_one will create master_one_lab_one LAB

                    master_three_child_one will create a master_three_child_one_lab_three LAB
                    master_three_child_two will create a master_three_child_two_lab_four LAB

                    master_four_child_one will create a master_four_child_one_lab_five LAB
                    master_four_child_two will create a master_four_child_two_lab_six LAB

                        master_three_child_one_lab_three LAB will claim its account
                        master_four_child_one_lab_five LAB will claim its account



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
    logging.info(json.dumps(children.json()["data"], indent=4))


    if account.json()["data"].get("child_account_idxs"):
        assert_equals(len(account.json()["data"].get("child_account_idxs")), len(children.json()["data"]))
        assert_equals(account.json()["data"].get("child_account_idxs"), [e["parent_idx"] for e in children.json()["data"]])

    return




def boilerplate_get_float_accounts(requester):
    response = AccountApis.get_float_accounts(requester)
    assert_equals(response.status_code, 200)
    return response.json()["data"]


#############--------------Test Begins----------------------------------------##



def test_float_account_master_admin():
    boilerplate_org_registeration(admin, master_admin)


def test_register_admin_children():
    logging.info(f"Trying to register a child_one for admin account {child_one}")
    boilerplate_child_registeration(admin, child_one)

    logging.info(f"Trying to register a child_two for admin account {child_two}")
    boilerplate_child_registeration(admin, child_two)



def test_float_account_child_one_master_one():
    logging.info("Registering master_one with child_one of admin account")
    boilerplate_org_registeration(child_one, master_one)



def test_float_account_child_one_master_two():
    logging.info("Registering master_two with child_one of admin account")
    boilerplate_org_registeration(child_one, master_two)




def test_float_account_child_two_master_three():
    logging.info("Registering master_three with child_two of admin account")
    boilerplate_org_registeration(child_two, master_three)



def test_float_account_child_two_master_four():
    logging.info("Registering master_four with child_two of admin account")
    boilerplate_org_registeration(child_two, master_four)


##-------------------**claim accounts ----------------------------------------##
##only master_one created by child_one of admin and master_three created by
##child two of admin will be claimed, master_four created by child_two of admin
## for the time being
##master_two will be claimed later on after issuing them certificates

def test_claim_account_master_one():
    logging.info("Claiming master one")
    boilerplate_claim_account(master_one)

"""
def test_claim_account_master_three():
    logging.info("Claiming master three")
    boilerplate_claim_account(master_three)

def test_claim_account_master_four():
    logging.info("Claiming master four")
    boilerplate_claim_account(master_four)


##----------------------------------------------------------------------------##


##----------------Registring child for masters -------------------------------##
##TODO, the children must have extension of email of parent organization
def test_register_master_three_children():
    logging.info(f"Trying to register a child_one for master_three account {master_three_child_one}")
    boilerplate_child_registeration(master_three, master_three_child_one)

    logging.info(f"Trying to register a child_two for master_three account {master_three_child_two}")
    boilerplate_child_registeration(master_three, master_three_child_two)

##TODO, the children must have extension of email of parent organization
def test_register_master_four_children():
    logging.info(f"Trying to register a child_one for master_four account {master_four_child_one}")
    boilerplate_child_registeration(master_four, master_four_child_one)

    logging.info(f"Trying to register a child_two for master_three account {master_four_child_two}")
    boilerplate_child_registeration(master_four, master_four_child_two)

##---------------------end----------------------------------------------------##


def test_get_orgnization_account_api_result():
    ##to see whether the api resultof get_organization_account api is good or nto
    account= AccountApis.get_organization_account(admin)
    assert_equals(account.status_code, 200)
    logging.info(json.dumps(account.json(), indent=4))




def test_get_orgnization_children_api_result():
    ##to see whether the api resultof get_organization_account api is good or nto
    children= AccountApis.get_children(admin)
    assert_equals(children.status_code, 200)
    logging.info(json.dumps(children.json(), indent=4))


def test_get_orgnization_float_accounts_api_result():
    ##to see whether the api resultof get_organization_account api is good or nto
    float_accounts = boilerplate_get_float_accounts(admin)
    logging.info(json.dumps(float_accounts, indent=4))


##----------------CHeck if child_account_idxs in parents are updated----------##
def test_master_three_children():
    logging.info("We have already created two children for master_three, lets check the response")
    boilerplate_check_children(master_three)


def test_master_four_children():
    logging.info("We have already created two children for master_four, lets check the response")
    boilerplate_check_children(master_four)


def test_admin_children():
    logging.info("We have already created two children for admin, lets check the response")
    boilerplate_check_children(admin)


##-------------Check if float account by admins are properly registered or not--#
## till now, admin has registered five masters, out of four has been registered-#
##by its children, lets check that--------------------------------------------##


def test_admin_float_accounts():
    logging.info(f"Checking float accounts of the admin {admin}")
    float_accounts = boilerplate_get_float_accounts(admin)
    logging.info(json.dumps(float_accounts, indent=4))

    logging.info("The length of float accounts for admin must be 5")
    assert_equals(len(float_accounts), 5)

    float_account_children = [acc for acc in float_accounts if \
                        acc.get("child_zero_pub")]

    logging.info("The length of float accounts created by admin children must be 4")
    assert_equals(len(float_account_children), 4)


def test_admin_child_one_float_accounts():
    logging.info(f"Checking float accounts of the admin child_one {child_one}")
    float_accounts = boilerplate_get_float_accounts(child_one)
    logging.info(json.dumps(float_accounts, indent=4))

    logging.info("The length of float accounts for admin child_one must be 2")
    assert_equals(len(float_accounts), 2)


def test_admin_child_two_float_accounts():
    logging.info(f"Checking float accounts of the admin child_two {child_one}")
    float_accounts = boilerplate_get_float_accounts(child_two)
    logging.info(json.dumps(float_accounts, indent=4))

    logging.info("The length of float accounts for admin child_two must be 2")
    assert_equals(len(float_accounts), 2)

##TODO make some tests to check the nonce and signed nonce
##lets check master_three orgnization account again, to see whether it has
##two children created above or not

def test_master_three_account():
    account= AccountApis.get_organization_account(master_three)
    logging.info(json.dumps(account.json()["data"], indent=4))



##----------------------## registering labs by master orgnizations -----------##
##first lets try to create lab by Admin, as it is not allowed to creat LAB role


def test_float_account_admin_lab_one():
    logging.info("Registering master_one_lab_one with  admin account, which must fail\
        as ADMIN role is not allowed to create LAB role")
    response = boilerplate_org_registeration(admin, master_one_lab_one)
    if response:
        assert_true(response.json()["error"])


def test_float_account_master_one_lab_one():
    account= AccountApis.get_organization_account(master_one)
    logging.info(json.dumps(account.json()["data"], indent=4))
    logging.info("Registering master_one_lab_one with master_one of admin account")
    response = boilerplate_org_registeration(master_one, master_one_lab_one)

##since master_two hasnt claimed this account, this must fail as unclaimed accounts
##arent allowed to do anything except recieveing certificates from the creators
def test_float_account_master_two_lab_two():
    logging.info("Registering master_two_lab_two with master_two, who was \
        created by child_one of admin account")
    response = boilerplate_org_registeration(master_two, master_two_lab_two)
    if response:
        assert_true(response.json()["success"])


def test_float_account_master_three_child_one_lab_three():
    logging.info("Registering master_three_child_one_lab_three with master_three_child_one, who is \
        child for master_three, master_three created by child_one of admin account")
    response = boilerplate_org_registeration(master_three_child_one,
                                    master_three_child_one_lab_three)
    if response:
        assert_true(response.json()["success"])






def test_float_account_master_three_child_two_lab_four():
    logging.info("Registering master_three_child_two_lab_four with master_three_child_two, who is \
        child for master_three, master_three created by child_one of admin account")
    response = boilerplate_org_registeration(master_three_child_two,
                                    master_three_child_two_lab_four)
    if response:
        assert_true(response.json()["success"])



def test_float_account_master_four_child_one_lab_five():
    logging.info("Registering master_four_child_one_lab_five with master_four_child_one, who is \
        child_one  for master_four, master_four created by child_two of admin account")
    response = boilerplate_org_registeration(master_four_child_one,
                                    master_four_child_one_lab_five)
    if response:
        assert_true(response.json()["success"])


def test_float_account_master_four_child_two_lab_six():
    logging.info("Registering master_four_child_two_lab_six with master_four_child_two, who is \
    child_two for master_four, master_three created by child_two of admin account")
    response = boilerplate_org_registeration(master_four_child_two,
                                    master_four_child_two_lab_six)
    if response:
        assert_true(response.json()["success"])


####################################################################################
################ Checking Children of Masters and the lab account screated by them##
###################################################################################


def test_float_account_master_three():
    logging.info("Fetching float_accounts created by master_three, this also counts\
    the float_accounts created by its children")
    float_accounts = boilerplate_get_float_accounts(master_three)
    logging.info(json.dumps(float_accounts, indent=4))

    logging.info("The length of float accounts for master three as its children\
        created two float accounts lab_three and lab_four, must be 2")
    assert_equals(len(float_accounts), 2)


def test_float_account_master_four():
    logging.info("Fetching float_accounts created by master_four, this also counts\
    the float_accounts created by its children")
    float_accounts = boilerplate_get_float_accounts(master_three)
    logging.info(json.dumps(float_accounts, indent=4))

    logging.info("The length of float accounts for master four as its children\
        created two float accounts lab_five and lab_six, must be 2")
    assert_equals(len(float_accounts), 2)

################################################################################
############CLaim account for lab_three and lab_five ###########################
################################################################################


def test_claim_account_master_three_chile_one_lab_three():
    logging.info("Claiming lab_three created by child_one of master three")
    boilerplate_claim_account(master_three_child_one_lab_three)

def test_claim_account_master_four_child_two_lab_six():
    logging.info("Claiming master three")
    boilerplate_claim_account(master_four_child_two_lab_six)



def test_check_all_organization_accounts():
    logging.info("Check all orgnization account present on the blockchain and their children")
    logging.info("Checking admin account and its children")
    account= AccountApis.get_organization_account(admin)
    logging.info(json.dumps(account.json()["data"], indent=4))
    boilerplate_check_children(admin)


    logging.info("Checking master_one account and its children")
    account= AccountApis.get_organization_account(master_one)
    logging.info(json.dumps(account.json()["data"], indent=4))
    boilerplate_check_children(master_one)

    logging.info("Checking lab_six account and its children")
    account= AccountApis.get_organization_account(master_four_child_two_lab_six)
    logging.info(json.dumps(account.json()["data"], indent=4))
    boilerplate_check_children(master_four_child_two_lab_six)

def test_float_account_user_one_lab_six():
    logging.info("Registering user_one with lab_six")
    boilerplate_org_registeration(master_four_child_two_lab_six, user_one)

"""
