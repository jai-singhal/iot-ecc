# from tinyimport registry
from Crypto.Cipher import AES
import hashlib, binascii
import random
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

from .graph import *
from .curve_registry import *


def get_curve_name(index = None):
    ec_curves = list(EC_CURVE_REGISTRY.keys())
    if index:
        return ec_curves[index]

    return random.choice(ec_curves)

def getCurve(name):
    curve_params = {}
    for k, v in EC_CURVE_REGISTRY.items():
        if name.lower() == k.lower():
            curve_params = v
    if curve_params == {}:
        raise ValueError("Unknown elliptic curve name")
    try:
        sub_group = SubGroup(curve_params["p"], curve_params["g"], curve_params["n"], curve_params["h"])
        curve = Curve(curve_params["a"], curve_params["b"], sub_group, name)
    except KeyError:
        raise RuntimeError("Missing parameters for curve %s" % name)
    return curve

def createHMAC(msg:list):
    set = msg[0]
    assert isinstance(set, bytes)

    h = HMAC.new(set, digestmod=SHA256)
    for m in msg[1:]:
        assert isinstance(m, bytes)
        h.update(m)
    return h.hexdigest()

def create_sha256_hash(msg:str):
    h = SHA256.new()
    h.update(msg.encode("utf-8"))
    return h.hexdigest()




def encrypt_AES_GCM(msg, setKey):
    aesCipher = AES.new(setKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, setKey):
    aesCipher = AES.new(setKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point, keysize=32, iters=10000):
    sha_instance = hashlib.sha256()
    sha_instance.update(str(point.x).encode("utf-8"))
    sha_instance.update(str(point.y).encode("utf-8"))
    salt = b'7G\xf6\xc3n\x01\xf7\xf3\xb46\xce\xfd.\x7f\xdfX'
    kdfKey = PBKDF2(sha_instance.digest(), salt, keysize, iters, hmac_hash_module=SHA256)
    return kdfKey
    
# def encrypt_(msg, setKey):
#     ciphertext, nonce, authTag = encrypt_AES_GCM(msg, setKey)
#     return (ciphertext, nonce, authTag)

# def dypt_(encryptedMsg, setKey):
#     (ciphertext, nonce, authTag) = encryptedMsg
#     plaintext = dypt_AES_GCM(ciphertext, nonce, authTag, setKey)
#     return plaintext