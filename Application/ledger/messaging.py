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

from sawtooth_sdk.protobuf import client_batch_submit_pb2
from sawtooth_sdk.protobuf import validator_pb2
import json
from errors.errors import ApiBadRequest
from errors.errors import ApiInternalError
import aiohttp
import asyncio
import time
from transactions.extended_batch import make_header_and_batch as extended_


import coloredlogs, logging
coloredlogs.install()

def load_json(data):
    try:
        request_json = json.loads(data.decode())
    except Exception as e:
        raise ApiBadRequest(f"Json cannot be parsed")
    return request_json

async def send(data, config):
    """
    batch_request = client_batch_submit_pb2.ClientBatchSubmitRequest()
    batch_request.batches.extend(batches)
    await conn.send(
        validator_pb2.Message.CLIENT_BATCH_SUBMIT_REQUEST,
        batch_request.SerializeToString(),
        timeout)
    """
    headers = {'Content-Type': 'application/octet-stream'}
    timeout = aiohttp.ClientTimeout(total=config.TIMEOUT)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(f"http://{config.REST_API_URL}/batches", data=data, headers=headers) as response:
                data = await response.read()
    except Exception as e:
        logging.error("Blockchain rest-api is unreachable, Please fix it dude")
        raise ApiInternalError("Blockchain rest-api is unreachable, Please fix it dude")
    return data




async def wait_for_status(batch_id, config):
    '''Wait until transaction status is not PENDING (COMMITTED or error).
       'wait' is time to wait for status, in seconds.
    '''
    headers = {'Content-Type': 'application/json'}
    waited = 0
    start_time = time.time()
    wait = config.TIMEOUT
    timeout = aiohttp.ClientTimeout(total=config.TIMEOUT)
    while waited < wait:
        async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"http://{config.REST_API_URL}/batch_statuses?id={batch_id}", headers=headers) as response:
                    await asyncio.sleep(0.5)
                    data = await response.read()
        try:
            data = load_json(data)
            status = data['data'][0]['status']
        except Exception as e:
            logging.error("Error in wait for status")
            logging.error(e)
            status = ""
            pass

        waited = time.time() - start_time
        logging.info(f"Trying again, to check block status BLOCK-STATUS {status}")
        if status != 'PENDING':
            break
    if status == "COMMITTED":
        logging.info("Transaction successfully submittted")
        return True

    elif status == "PENDING":
        logging.error("Transaction submitted but timed out")
        raise ApiInternalError("Transaction submitted but timed out")
    elif status == "UNKNOWN":
        logging.error("Something went wrong. Try again later")
        raise ApiInternalError("Something went wrong. Try again later")
    elif status == "INVALID":
        logging.error("Transaction submitted to blockchain is invalid")
        raise ApiInternalError("Transaction submitted to blockchain is invalid")

    else:
        logging.error("Error in the transaction {%s}"%data['data'][0]['message'])
        raise ApiBadRequest("Error in the transaction {%s}"%data['data'][0]['message'])
    return False




async def check_batch_status(conn, batch_id):
    status_request = client_batch_submit_pb2.ClientBatchStatusRequest(
        batch_ids=[batch_id], wait=True)
    validator_response = await conn.send(
        validator_pb2.Message.CLIENT_BATCH_STATUS_REQUEST,
        status_request.SerializeToString())

    status_response = client_batch_submit_pb2.ClientBatchStatusResponse()
    status_response.ParseFromString(validator_response.content)
    batch_status = status_response.batch_statuses[0].status
    if batch_status == client_batch_submit_pb2.ClientBatchStatus.INVALID:
        invalid = status_response.batch_statuses[0].invalid_transactions[0]
        raise ApiBadRequest(invalid.message)
    elif batch_status == client_batch_submit_pb2.ClientBatchStatus.PENDING:
        raise ApiInternalError("Transaction submitted but timed out")
    elif batch_status == client_batch_submit_pb2.ClientBatchStatus.UNKNOWN:
        raise ApiInternalError("Something went wrong. Try again later")
