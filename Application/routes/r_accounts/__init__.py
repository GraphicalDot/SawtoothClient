

from sanic import Blueprint

from .login import LOGIN_BP
from .users import USERS_BP
from .organization import ACCOUNT_ORG_BP
ACCOUNTS_BP = Blueprint.group(LOGIN_BP, USERS_BP, ACCOUNT_ORG_BP, url_prefix='/accounts')
