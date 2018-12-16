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
# ------------------------------------------------------------------------------

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
# ------------------------------------------------------------------------------

import logging

from sanic.response import json
from sanic import Blueprint
from sanic.exceptions import SanicException


ERRORS_BP = Blueprint('errors')
LOGGER = logging.getLogger(__name__)
DEFAULT_MSGS = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    501: 'Not Implemented',
    503: 'Internal Error'
}


def add_status_code(code):
    def class_decorator(cls):
        cls.status_code = code
        return cls
    return class_decorator



class ApiException(SanicException):
    def __init__(self, message=None, status_code=None):
        super().__init__(message)
        if status_code is not None:
            self.status_code = status_code
        if message is None:
            self.message = DEFAULT_MSGS[self.status_code]
        else:
            self.message = message



@add_status_code(400)
class CustomError(ApiException):
    def __init__(self, message="This is a custom error", status_code=None):
        super().__init__(message)


@add_status_code(400)
class PasswordStrengthError(ApiException):
    def __init__(self, message="The Password should have Caps, Small, \
    special chars, numbers and must be of atleast 8 length", status_code=None):
        super().__init__(message)




##Errors related to Account creation
##---------------------ACCOUNT ERRORS --------------------------------##

@add_status_code(400)
class PendingAccountError(ApiException):
    def __init__(self, message="The user doenst have corresponding float account",
                        status_code=None):
        super().__init__(message)


@add_status_code(400)
class AccountError(ApiException):
    def __init__(self, message="This Account already exists with us",
                        status_code=None):
        super().__init__(message)


@add_status_code(400)
class ClaimAccountError(ApiException):
    def __init__(self, message="The user already has claimed this account",
                        status_code=None):
        super().__init__(message)


@add_status_code(400)
class AccountCreationError(ApiException):
    def __init__(self, message="This user is not allowed to create accounts",
                                    status_code=None):
        super().__init__(message)

##---------------------ACCOUNT ERRORS END --------------------------------##






@add_status_code(400)
class AssetError(ApiException):
    def __init__(self, message="This Asset cannot be created",
                                    status_code=None):
        super().__init__(message)




@add_status_code(400)
class AssetCreationError(ApiException):
    def __init__(self, message="Asset cant be created", status_code=None):
        super().__init__(message)


@add_status_code(400)
class DBError(ApiException):
    def __init__(self, message="DB Transaction failed", status_code=None):
        super().__init__(message)

@add_status_code(400)
class InValidAccountAddress(ApiException):
    def __init__(self, message="This is not a valid account address", status_code=None):
        super().__init__(message)



@add_status_code(400)
class InvalidValidityPeriod(ApiException):
    def __init__(self, message="Invalid validity period for document, \
                    it must be greater than atleast 30 days", status_code=None):
        super().__init__(message)



@add_status_code(400)
class NoAssociatedAssets(ApiException):
    def __init__(self, message="There is not a single asset associated with \
                    this account address", status_code=None):
        super().__init__(message)


@add_status_code(400)
class InValidAssetAddress(ApiException):
    def __init__(self, message="This is not a valid asset address", status_code=None):
        super().__init__(message)


@add_status_code(400)
class EmptyAssetAddress(ApiException):
    def __init__(self, message="This asset address has no asset to share",
                                                            status_code=None):
        super().__init__(message)



@add_status_code(400)
class NonEmptyAssetAddress(ApiException):
    def __init__(self, message="This asset address already has an asset",
                                                            status_code=None):
        super().__init__(message)


@add_status_code(400)
class AssetAuthorizationError(ApiException):
    def __init__(self, message="This asset is not owned by the user",
                                                            status_code=None):
        super().__init__(message)


@add_status_code(400)
class ParentKeysError(ApiException):
    def __init__(self, message="The menmonic and the keys for the parent doesnt match", status_code=None):
        super().__init__(message)



@add_status_code(400)
class ApiBadRequest(ApiException):
    pass


@add_status_code(401)
class ApiUnauthorized(ApiException):
    pass


@add_status_code(403)
class ApiForbidden(ApiException):
    pass


@add_status_code(404)
class ApiNotFound(ApiException):
    pass


@add_status_code(501)
class ApiNotImplemented(ApiException):
    pass


@add_status_code(500)
class ApiInternalError(ApiException):
    pass


@ERRORS_BP.exception(ApiException)
def api_json_error(request, exception):
    return json({
        'message': exception.message,
        'error': True,
        'success': False
    }, status=exception.status_code)


@ERRORS_BP.exception(Exception)
def json_error(request, exception):
    try:
        code = exception.status_code
    except AttributeError:
        code = 500
    LOGGER.exception(exception)
    return json({
        'error': exception.args[0]
    }, status=code)
