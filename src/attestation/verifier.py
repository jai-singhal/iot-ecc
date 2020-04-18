from src.utils import ecc
import pickle, time, json
import random
import uuid
import sys, os
from timeit import default_timer as timer
from tqdm import tqdm
import requests
import secrets, binascii
from itertools import islice
import math
import logging

logging.basicConfig(
    format='%(asctime)s - %(message)s', 
    datefmt='%d-%b-%y %H:%M:%S', 
    level=logging.INFO,
    filename="verifer.log",
    filemode='w'
)


CONFIGPATH = "../../config/config.json"
if not os.path.exists(CONFIGPATH):
    logging.error("CONFIG FILE NOT FOUND!!")
    sys.exit(-1)

class Verifier():
    def __init__(self, url="",block_size=1000,word_size=32,memory_filepath=""):
        self.verifierData = {}
        self.fillverifierData(url)
        self.BLOCK_SIZE=block_size
        self.WORD_SIZE=word_size
        self.NUM_OF_BLOCKS=0
        self.MEMEMORY_FILEPATH = memory_filepath
        self.total_hash_time=0

    def fillverifierData(self, CURR_IOT_DEVICE_BASEURL):
        self.verifierData["device_id"] = str(uuid.uuid4())
        self.verifierData["curve_name"] = ecc.get_curve_name(6) # random curve
        self.CURR_IOT_DEVICE_BASEURL = CURR_IOT_DEVICE_BASEURL


    def newIOTDeviceRegistration(self):
        response = requests.post(
            url = self.CURR_IOT_DEVICE_BASEURL + "/ecc/attestation/client/register/", 
            data = {
                "device_id": self.verifierData["device_id"],
                "curve_name": self.verifierData["curve_name"]
            }
        )
        response = response.json()

        if response["status"]:
            self.curve = ecc.getCurve(self.verifierData["curve_name"])
            return True
        else:
            logging.error("error:", response["error"])
            return False

    
    def keyExchange(self):
        # generate a
        if self.curve == None:
            return False

        tick = timer()
        privateKey = secrets.randbelow(self.curve.field.n)
        clientPublicKey = privateKey*(self.curve).g # privKey*curve
        tock = timer()

        data = {
            "device_id": self.verifierData["device_id"],
            "clipubKey": binascii.hexlify(pickle.dumps(clientPublicKey)),
            "clikeygentime": (tock-tick)*(10**3)
        }

        response = requests.post(
            url = self.CURR_IOT_DEVICE_BASEURL + "/ecc/attestation/keyexchange/", 
            data=data
        )
        response = response.json()
        if not response["status"]:
            logging.error("error", response["error"])
            return False

        serverPubKey = pickle.loads(binascii.unhexlify(response["pubKey"]))
        self.secretKey = ecc.ecc_point_to_256_bit_key(serverPubKey*privateKey)
        return True

    def sendVerificationMessage(self, msg:str):
        tick = timer()
        ct, nonce, tag = ecc.encrypt_AES_GCM(
            msg.encode("utf-8"), 
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
                "encr_time": (tock-tick)*(10**3),
                "keysize": 256
            }
        )
        if response.status_code == 200:
            ############################verifying sigma###############################
            response=response.json()
            if(response["status"]):
                encryptedMsg=response['msg']
                tag, nonce, ct = encryptedMsg[0:32], encryptedMsg[32:64], encryptedMsg[64:]
                ct = binascii.unhexlify(ct)
                tag = binascii.unhexlify(tag)
                nonce = binascii.unhexlify(nonce)
                decryptedMsg = ecc.decrypt_AES_GCM(ct, nonce, tag, self.secretKey)
                decryptedMsg = decryptedMsg.decode("utf-8")
                
                prover_sigma=decryptedMsg
                verifier_sigma=self.generateSigma()
                if(prover_sigma!=verifier_sigma):
                    return False
                return True
            else:
                logging.error(response["error"])
                return False
        else:
            logging.error("error:response status : "+str(response.status))
            return False


    def generateSiBSiW(self):
        self.SiB = random.randint(0, self.NUM_OF_BLOCKS-1)
        self.SiW = random.randint(0, self.BLOCK_SIZE-1)
        return (self.SiB, self.SiW)
    
    def generateSigma(self):
        boi=self.memoryBlocks[self.SiB]
        tick = timer()
        sigma=ecc.create_sha256_hash(str(boi))
        tock = timer()
        sha_time=(tock-tick)*(10**3)
        self.total_hash_time += sha_time
        logging.info("Time to create SHA256 is: {} ms".format(sha_time))
        return str(sigma)

    def readMemory(self, filepath):
        if not os.path.exists(filepath):
            logging.error("file not found")
            sys.exit(-1)
        
        with open(filepath, "r") as fin:
            fcontent = fin.read()
            self.NUM_OF_BLOCKS = math.ceil(len(fcontent)/self.BLOCK_SIZE)
            self.memoryBlocks = [
                fcontent[i:i+self.BLOCK_SIZE] 
                for i in range(0, len(fcontent), self.BLOCK_SIZE)
            ]

def main():
    print("-----------Verification starts------------")
    print("Watch verififer.log")
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

    verifier = Verifier(
        url=BASEURL_CLIENT1,
        block_size=BLOCK_SIZE,
        word_size=WORD_SIZE,
        memory_filepath=MEMORY_FILEPATH
    )
    verifier.readMemory(MEMORY_FILEPATH)
    verifier.newIOTDeviceRegistration()
    verifier.keyExchange()
    iteration=1
    while(True):
        (sib,siw)=verifier.generateSiBSiW()
        stat=verifier.sendVerificationMessage(str(sib)+","+str(siw))
        if stat:
            logging.info("iter["+str(iteration)+"] : "+"verification successful")
            iteration+=1
            continue
        else:
            logging.info("iter["+str(iteration)+"] : "+"verification failed!!!!!")
            break
    

if __name__ == "__main__":
    main()


