

from .addresser import address_is
from ledger import deserialize_state
from . import addresser
import coloredlogs, logging
coloredlogs.install()



class aobject(object):
    """Inheriting this class allows you to define an async __init__.

    So you can create objects by doing something like `await MyClass(params)`
    """
    async def __new__(cls, *a, **kw):
        instance = super().__new__(cls)
        await instance.__init__(*a, **kw)
        return instance

    async def __init__(self):
        pass


class ResolveAddress(aobject):
    async def __init__(self, address, rest_api_url):
        self.address = address

        self.address_type, self.account_index = addresser.address_is(address)
        logging.info(f"{address}, {self.address_type}, {self.account_index}")
        print (f"{address}, {self.address_type}, {self.account_index}")
        self.rest_api_url = rest_api_url

        self.data = None
        if self.address_type=="FLOAT_ACCOUNT":
            logging.info("Address is FLOAT_ACCOUNT")
            self.type = "FLOAT_ACCOUNT"
            self.data = await deserialize_state.deserialize_float_account(
                        self.rest_api_url, self.address)



        elif self.address_type=="ORGANIZATION_ACCOUNT":
            logging.info("Address is ORGANIZATION_ACCOUNT")
            self.type = "ORGANIZATION_ACCOUNT"
            self.data = await deserialize_state.deserialize_org_account(
                        self.rest_api_url, self.address)


        elif self.address_type=="CHILD_ACCOUNT":
            logging.info("Address is CHILD_ACCOUNT")
            self.type = "CHILD_ACCOUNT"
            self.data = await deserialize_state.deserialize_child(
                        self.rest_api_url, self.address)


        elif self.address_type=="USER_ACCOUNT":
            logging.info("Address is USER_ACCOUNT")
            self.type = "USER_ACCOUNT"
            self.data = await deserialize_state.deserialize_user(
                        self.rest_api_url, self.address)


        elif self.address_type == "CREATE_ASSET":
            logging.info("Address is CREATE_ASSET")
            self.type = "CREATE_ASSET"
            self.data = await deserialize_state.deserialize_asset(
                        self.rest_api_url, self.address)

        elif self.address_type == 'SHARE_ASSET':
            logging.info("Address is SHARE_ASSET")

            self.data = await deserialize_state.deserialize_share_asset(
            self.rest_api_url, self.address)

        elif self.address_type == "RECEIVE_ASSET":
            logging.info("Address is RECEIVE_ASSET")
            self.type = "RECEIVE_ASSET"
            self.data = await deserialize_state.deserialize_receive_asset(
                        self.rest_api_url, self.address)

        elif self.address_type == "SHARED_SECRET":
            logging.info("Address is SHARED_SECRET")
            self.type = "SHARE_SECRET"
            self.data = await deserialize_state.deserialize_share_secret(
                        self.rest_api_url, self.address)
        else:
            logging.info("Address is Unknown")
