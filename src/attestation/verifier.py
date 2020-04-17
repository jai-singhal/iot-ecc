from ..utils import ecc
import pickle, time, json
import random
import uuid
import sys, os
from timeit import default_timer as timer
from tqdm import tqdm
import requests
import secrets, binascii
from itertools import islice

CONFIGPATH = "../config/config.json"
if not os.path(CONFIGPATH).exists():
    print("CONFIG FILE NOT FOUND!!")
    raise FileNotFoundError
# https://pypi.org/project/tinydb/
# dbECC = TinyDB('../db/serverdbECC.json', 
#     indent=4, separators=(',', ': '), 
#     default_table="device_info",
#     # storage=CachingMiddleware(JSONStorage)
# )
# dbECCData = TinyDB('../db/serverdbECC.json', 
#     indent=4, separators=(',', ': '), 
#     default_table="data",
#     # storage=CachingMiddleware(JSONStorage)
# )

class Verifier():
    def __init__(self, url="",block_size=1000,word_size=32,memory_filepath=""):
        self.verifierData = {}
        self.fillverifierData(url)
        self.BLOCK_SIZE=block_size
        self.WORD_SIZE=word_size
        self.NUM_OF_BLOCKS=0
        self.MEMEMORY_FILEPATH = memory_filepath

    def fillverifierData(self, CURR_IOT_DEVICE_BASEURL):
        self.verifierData["device_id"] = str(uuid.uuid4())
        self.verifierData["curve_name"] = ecc.get_curve_name(6) # random curve
        self.CURR_IOT_DEVICE_BASEURL = CURR_IOT_DEVICE_BASEURL


    def newIOTDeviceRegistration(self):
        response = requests.post(
            url = self.CURR_IOT_DEVICE_BASEURL + "/ecc/attestation/client/register/", 
            data = json.dumps(self.verifierData)
        )
        response = response.json()

        if response["status"]:
            self.curve = ecc.getCurve(self.verifierData["curve_name"])
            return True
        else:
            print("error:", response["error"])
            return False

    
    def keyExchange(self):
        # generate a
        if self.curve == None:
            return False

        tick = timer()
        privateKey = secrets.randbelow(curve.field.n)
        clientPublicKey = privateKey*curve.g # privKey*curve
        tock = timer()

        data = {
            "device_id": self.verifierData["device_id"],
            "clipubKey": binascii.hexlify(pickle.dumps(clientPublicKey)),
            "clikeygentime": (tock-tick)*(10**9)
        }

        response = requests.post(
            url = self.CURR_IOT_DEVICE_BASEURL + "/ecc/attestation/keyexchange/", 
            data=data
        )
        response = response.json()
        if not response["status"]:
            print("error", response["error"])
            return False

        serverPubKey = pickle.loads(binascii.unhexlify(response["pubKey"]))
        self.secretKey = ecc.ecc_point_to_256_bit_key(serverPubKey*privateKey)
        return True

    def sendVerificationMessage(self, msg):
        tick = timer()
        ct, nonce, tag = ecc.encrypt_AES_GCM(
            msg, 
            self.secretKey
        )
        ct = binascii.hexlify(ct).decode("utf-8")
        tag = binascii.hexlify(tag).decode("utf-8")
        nonce = binascii.hexlify(nonce).decode("utf-8")

        cryptogram = tag + nonce + ct
        tock = timer()
        response = requests.post(
            url = self.CURR_IOT_DEVICE_BASEURL + "/ecc/attestation/send/msg/", 
            data = {
                "encryptedMsg":cryptogram,
                "device_id": self.verifierData["device_id"],
                "encr_time": (tock-tick)*(10**9),
                "keysize": 256
            }
        )
        if response.status_code == 200:
            return True
        else:
            return False


    def generateSiBSiW(self):
        self.SiB = random.randint()%self.NUM_OF_BLOCKS
        self.SiW = random.randint()%self.BLOCK_SIZE
        return (self.SiB, self.SiW)
    

    def readMemory(self, filepath):
        if not os.path(filepath).exists():
            raise FileNotFoundError
        
        with open(filepath, "r") as fin:
            fcontent = fin.read()
            self.NUM_OF_BLOCKS = len(fcontent)/self.BLOCK_SIZE
            self.memoryBlocks = [
                fcontent[i:i+self.BLOCK_SIZE] 
                for i in range(0, len(fcontent), self.BLOCK_SIZE)
            ]

def main():
    with open(CONFIGPATH, "r") as f:
        config = json.loads(f.read())

    if config["production"] == True:
        pd = "local"
    else:
        pd = "development"

    BASEURL_SERVER= config[pd]["server"]["BASEURL_SERVER"]
    BLOCK_SIZE= config[pd]["server"]["BLOCK_SIZE"]
    WORD_SIZE= config[pd]["server"]["WORD_SIZE"]
    MEMORY_FILEPATH = config[pd]["client"]["MEMORY_FILEPATH"]
    BASEURL_CLIENT1 = config[pd]["client"]["BASEURL_CLIENT1"]
    BASEURL_CLIENT2 = config[pd]["client"]["BASEURL_CLIENT2"]

    verifier = Verifier(url=BASEURL_CLIENT1,block_size=BLOCK_SIZE,word_size=WORD_SIZE,memory_filepath=MEMORY_FILEPATH)
    verifier.newIOTDeviceRegistration()
    verifier.keyExchange()
    verifier.sendVerificationMessage("sb[i],sw[i]")
    verifier.checkSigma()
    

if __name__ == "__main__":
    main()