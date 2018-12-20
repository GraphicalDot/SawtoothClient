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
# -----------------------------------------------------------------------------

import hashlib
from uuid import uuid4
from errors import errors
from sawtooth_sdk.protobuf import batch_pb2, transaction_pb2

from addressing import addresser
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
import coloredlogs, logging
coloredlogs.install()





def prepare_transaction(txn_key, payload, header, batch_key):
    """Takes the serialized RBACPayload and creates a batch_list, batch
    signature tuple.
    Args:
        txn_key (sawtooth_signing.Signer): The txn signer's key pair.
        payload (bytes): The serialized RBACPayload.
        header (bytes): The serialized TransactionHeader.
        batch_key (sawtooth_signing.Signer): The batch signer's key pair.
    Returns:
        tuple
            The zeroth element is a BatchList, and the first element is
            the batch header_signature.
    """

    transaction = transaction_pb2.Transaction(
        payload=payload,
        header=header,
        header_signature=txn_key.sign(header))

    return transaction.header_signature, transaction

def multi_transactions_batch(transactions, batch_key):
    if type(transactions) != list:
        raise CustomError("Transactions must be instance of list")

    batch_header = batch_pb2.BatchHeader(
        signer_public_key=batch_key.get_public_key().as_hex(),
        transaction_ids=[transaction.header_signature for transaction in transactions]).SerializeToString()

    batch = batch_pb2.Batch(
        header=batch_header,
        header_signature=batch_key.sign(batch_header),
        transactions=transactions)

    batch_list_bytes = BatchList(batches=[batch]).SerializeToString()
    return batch.header_signature, batch_list_bytes



def make_header_and_batch(payload, inputs, outputs, txn_key, batch_key,
            dependencies=None):

    header = make_header(
        inputs=inputs,
        outputs=outputs,
        payload_sha512=hashlib.sha512(
            payload.SerializeToString()).hexdigest(),
        signer_pubkey=txn_key.get_public_key().as_hex(),
        batcher_pubkey=batch_key.get_public_key().as_hex(),
        dependencies=dependencies)

    return prepare_transaction(
        txn_key=txn_key,
        payload=payload.SerializeToString(),
        header=header.SerializeToString(),
        batch_key=batch_key)


def make_header(inputs,
                outputs,
                payload_sha512,
                signer_pubkey,
                batcher_pubkey, dependencies):

    if dependencies:
        dependencies = [dependencies]
    else:
        dependencies=[]
    header = transaction_pb2.TransactionHeader(
        inputs=inputs,
        outputs=outputs,
        batcher_public_key=batcher_pubkey,
        dependencies=dependencies,
        family_name=addresser.FAMILY_NAME,
        family_version='1.0',
        nonce=uuid4().hex,
        signer_public_key=signer_pubkey,
        payload_sha512=payload_sha512)
    return header
