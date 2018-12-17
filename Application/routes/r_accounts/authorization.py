
from functools import wraps

import bcrypt

from itsdangerous import BadSignature
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

from sanic.response import json
from sanic.log import logger

from errors.errors import ApiUnauthorized
from db.accounts_query import fetch_info_by_email

import coloredlogs, logging
coloredlogs.install()



def generate_auth_token(secret_key, email, public_key):
    serializer = Serializer(secret_key)
    token = serializer.dumps({'email': email, 'public_key': public_key})
    return token.decode('ascii')


def deserialize_auth_token(secret_key, token):
    serializer = Serializer(secret_key)
    return serializer.loads(token)




def authorized():
    """Verifies that the token is valid and belongs to an existing user"""
    def decorator(func):
        @wraps(func)
        async def decorated_function(request, *args, **kwargs):
            logger.debug(request.headers)
            if request.headers.get("token") is None:
                logging.error("No bearer token provided")
                raise ApiUnauthorized("No bearer token provided")
            try:
                email = deserialize_auth_token(
                    request.app.config.SECRET_KEY,
                    request.headers["token"]).get('email')
                auth_info = await fetch_info_by_email(
                        email, request.app)
                if auth_info is None:
                    logging.error("No user exists")
                    raise ApiUnauthorized(
                        "The user doesnt exists")
                #kwargs["parent"] = auth_info
            except BadSignature:
                logging.error("Invalid bearer token")
                raise ApiUnauthorized("Invalid bearer token")
            response = await func(request, auth_info)
            return response
        return decorated_function
    return decorator
