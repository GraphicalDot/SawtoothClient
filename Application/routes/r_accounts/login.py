
from sanic import Blueprint
from db.accounts_query import fetch_info_by_email, update_password
import re
from .authorization import generate_auth_token
from sanic.log import logger
from sanic import response
from encryption.key_derivations import check_bcrypt
#USERS_BP = Blueprint('users')
from errors.errors import ApiUnauthorized, PasswordStrengthError
from .authorization import authorized
from routes.route_utils import user_mnemonic_frm_password, validate_fields,\
        set_change_password

import coloredlogs, logging
coloredlogs.install()

from sanic import Blueprint
LOGIN_BP = Blueprint('login', url_prefix='/')


#from api.authorization import authorized
@LOGIN_BP.post('login')
async def login(request):
    required_fields = ['email', 'password']
    validate_fields(required_fields, request.json)
    password = bytes(request.json.get('password'), 'utf-8')
    auth_info = await fetch_info_by_email(
            request.json.get('email'), request.app)
    if auth_info is None:
        raise ApiUnauthorized("No user with that email exists or user havent claimed his/her account yet")
    hashed_password = auth_info.get('password')
    if not check_bcrypt(password, hashed_password):
        logging.info("Incorrect email or password")
        raise ApiUnauthorized("Incorrect email or password")

    if auth_info["role"] != "ADMIN":
        if auth_info["deactivate"]:
            raise ApiUnauthorized("Your account has been freezed,\
                Please contact your parent organization")
    token = generate_auth_token(
        request.app.config.SECRET_KEY,
        auth_info.get('email'),
        auth_info.get('acc_zero_pub'))


    return response.json(
        {
            'authorization': token
        })



#from api.authorization import authorized
@LOGIN_BP.post('change_password')
async def change_password(request):
    required_fields = ['email', 'password', "new_password"]
    validate_fields(required_fields, request.json)
    password = bytes(request.json.get('password'), 'utf-8')
    auth_info = await fetch_info_by_email(
            request.json.get('email'), request.app)

    if auth_info is None:
        raise ApiUnauthorized("No user with that email exists or user havent claimed his/her account yet")

    hashed_password = auth_info.get('password')
    logging.info(f"THis is the hashed passwordin the database {hashed_password}")
    logging.info(f"THis is the password entered by the user {request.json['password']}")
    if not check_bcrypt(password, hashed_password):
        logging.info("Incorrect email or password")
        raise ApiUnauthorized("Incorrect email or password")

    if auth_info["role"] != "ADMIN":
        if auth_info["closed"]:
            raise ApiUnauthorized("Your account has been freezed,\
                Please contact your parent organization")


    ##checking the newpass word strength
    required_pattern = re.compile('(?=.{6,})(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&*()])')
    if not required_pattern.match(request.json["new_password"]) or \
                        len(request.json["new_password"]) <= 8:
            raise PasswordStrengthError()
    h_password, salt, encrypted_mnemonic = await set_change_password(request.app,
                            auth_info, request.json["new_password"])

    logging.info(f"NEW hashed password {h_password}")

    changes =await update_password(request.app, request.json["email"],
                h_password, salt, encrypted_mnemonic)

    ##This is just to check whether the database has been updated with the new password or not

    auth_info = await fetch_info_by_email(
                request.json.get('email'), request.app)

    mnemonic = await user_mnemonic_frm_password(request.app, auth_info,
                                                    request.json["new_password"])
    logging.info(f"This is the mnemonic decrypted with new password {mnemonic}")
    return response.json(
        {
            'success': True,
            "error": False,
            "data": None,
            "message": "Password change is successful"
        })
