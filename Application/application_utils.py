
from errors.errors import ApiBadRequest, ApiInternalError
import pytz
from sanic.log import logger
import random
import datetime
import base64
import hashlib
import asyncio
from errors.errors import ApiInternalError





def validate_fields(required_fields, request_json):
    try:
        for field in required_fields:
            if request_json.get(field) is None:
                raise ApiBadRequest("{} is required".format(field))
    except (ValueError, AttributeError):
        raise ApiBadRequest("Improper JSON format")
