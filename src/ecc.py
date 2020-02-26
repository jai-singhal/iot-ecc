from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii

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

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()
    
def encrypt_ECC(msg, secretKey):
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    return (ciphertext, nonce, authTag)

def decrypt_ECC(encryptedMsg, secretKey):
    (ciphertext, nonce, authTag) = encryptedMsg
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext