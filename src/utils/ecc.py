from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii
import random
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

def get_curve_name(index = None):
    EC_CURVE_REGISTRY = [
        "brainpoolP192r1",
        "brainpoolP224r1", 
        "brainpoolP256r1", 
        "brainpoolP320r1", 
        "brainpoolP384r1", 
        "brainpoolP512r1", 
        "secp192r1", 
        "secp224r1", 
        "secp256r1", 
        "secp384r1", 
        "secp521r1", 
    ]
    if index:
        return EC_CURVE_REGISTRY[index]
    else:
        return random.choice(EC_CURVE_REGISTRY)

def getCurve(cr):
    curve = registry.get_curve(cr)
    return curve


def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point, keysize=256, iters=10000):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, byteorder= 'big'))
    sha.update(int.to_bytes(point.y, 32, byteorder='big'))
    salt = b'7G\xf6\xc3n\x01\xf7\xf3\xb46\xce\xfd.\x7f\xdfX'
    kdfKey = PBKDF2(sha.digest(), salt, 32, iters, hmac_hash_module=SHA256)
    return kdfKey
    
def encrypt_ECC(msg, secretKey):
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    return (ciphertext, nonce, authTag)

def decrypt_ECC(encryptedMsg, secretKey):
    (ciphertext, nonce, authTag) = encryptedMsg
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext