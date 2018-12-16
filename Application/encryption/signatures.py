


from sawtooth_signing.secp256k1 import Secp256k1PublicKey
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from errors.errors import ApiInternalError
import binascii
#coloredlogs.install()
import coloredlogs, logging
coloredlogs.install()

##NOTE for both these functions "2334" is equivalent to 2334 as message 

def ecdsa_signature(private_key, message):
    secp_private = Secp256k1PrivateKey.from_hex(private_key)
    if isinstance(message, int):
        message = str(message)
        print (message)
    if isinstance(message, str):
        message = message.encode()
        print (message)
    raw_sig = secp_private.secp256k1_private_key.ecdsa_sign(message)
    signature = secp_private.secp256k1_private_key.ecdsa_serialize(raw_sig)
    return binascii.hexlify(signature)




def ecdsa_signature_verify(public_key, signature, raw_message):
    secp_public = Secp256k1PublicKey.from_hex(public_key)
    #unhexlify signature

    try:
        signature = binascii.unhexlify(signature)
    except Exception as e:
        logging.error("Signatures are not in valid hex format")
        raise ApiInternalError(e)

    unserialized = secp_public.secp256k1_public_key.ecdsa_deserialize(signature)


    if isinstance(raw_message, int):
        raw_message = str(raw_message)

    if isinstance(raw_message, str):
        raw_message = raw_message.encode()

    return secp_public.secp256k1_public_key.ecdsa_verify(raw_message, unserialized)
