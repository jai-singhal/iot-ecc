from ..utils import ecc
import pickle, time, json
import random
import uuid
import sys, os
from timeit import default_timer as timer
from tqdm import tqdm
import requests
import secrets, binascii

class ClientECC():
    def __init__(self, CURR_CLIENT_BASEURL, BASEURL_SERVER):
        self.clientData = {}
        self.CURR_CLIENT_BASEURL = CURR_CLIENT_BASEURL
        self.BASEURL_SERVER = BASEURL_SERVER

    def fillClientData(self):
        self.clientData["device_id"] = str(uuid.uuid4())
        self.clientData["curve_name"] = ecc.get_curve_name(6) # random curve
        self.clientData["latitude"] = random.uniform(-180,180)
        self.clientData["longitude"] = random.uniform(-90, 90)

    def clientRegistration(self):
        self.fillClientData()

        response = requests.post(
            url = self.BASEURL_SERVER + "/ecc/attestation/client/register/", 
            data = json.dumps(self.clientData)
        )
        response = response.json()

        if response["status"]:
            self.clientData["curve"] = ecc.getCurve(self.clientData["curve_name"])
            return True
        else:
            print("error:", response["error"])
            return False

    
    def keyExchange(self):
        # generate a
        curve = self.clientData["curve"]
        if curve == None:
            return False

        tick = timer()
        privateKey = secrets.randbelow(curve.field.n)
        clientPublicKey = privateKey*curve.g # privKey*curve
        tock = timer()

        data = {
            "device_id": self.clientData["device_id"],
            "clipubKey": binascii.hexlify(pickle.dumps(clientPublicKey)),
            "clikeygentime": (tock-tick)*(10**9)
        }

        response = requests.post(
            url = self.BASEURL_SERVER + "/ecc/attestation/keyexchange/", 
            data=data
        )
        response = response.json()
        if not response["status"]:
            print("error", response["error"])
            return False

        serverPubKey = pickle.loads(binascii.unhexlify(response["pubKey"]))
        self.clientData["secretKey"] = ecc.ecc_point_to_256_bit_key(serverPubKey*privateKey)
        
        return True

    def sendMessage(self, msg, filepath):
        tick = timer()
        ct, nonce, tag = ecc.encrypt_AES_GCM(
            msg, 
            self.clientData["secretKey"]
        )
        ct = binascii.hexlify(ct).decode("utf-8")
        tag = binascii.hexlify(tag).decode("utf-8")
        nonce = binascii.hexlify(nonce).decode("utf-8")

        cryptogram = tag + nonce + ct
        tock = timer()
        response = requests.post(
            url = self.BASEURL_SERVER + "/ecc/attestation/send/msg/", 
            data={
                "encryptedMsg":cryptogram,
                "filepath": filepath,
                "device_id": self.clientData["device_id"],
                "encr_time": (tock-tick)*(10**9),
                "keysize": 256
            }
        )
        if response.status_code == 200:
            return True
        else:
            return False
