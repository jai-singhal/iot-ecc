import requests
import secrets, binascii
from utils import ecc
import pickle, time, json
import random
import uuid
import sys, os
from timeit import default_timer as timer
from tqdm import tqdm

def clearDB():
    with open("../../db/serverdbECC.json", "w") as fout:
        fout.write("")
    # with open("../../db/serverdbRSA.json", "w") as fout:
    #     fout.write("")

clearDB()

#DATAPATH = "../../data/"
CONFIGPATH = "../../config/config.json"

class ClientECC():
    def __init__(self, CURR_CLIENT_BASEURL, BASEURL_SERVER):
        self.clientData = {}
        self.CURR_CLIENT_BASEURL = CURR_CLIENT_BASEURL
        self.BASEURL_SERVER = BASEURL_SERVER

    def fillClientData(self):
        self.clientData["device_id"] = str(uuid.uuid4())
        self.clientData["curve_name"] = ecc.get_curve_name(3) # random curve
        self.clientData["latitude"] = random.uniform(-180,180)
        self.clientData["longitude"] = random.uniform(-90, 90)

    def clientRegistration(self):
        self.fillClientData()

        response = requests.post(
            url = self.BASEURL_SERVER + "/ecc/post/client/register/", 
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
            "clikeygentime": (tock-tick)*(10**3)
        }

        response = requests.post(
            url = self.BASEURL_SERVER + "/ecc/post/keyexchange/", 
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
            url = self.BASEURL_SERVER + "/ecc/send/msg/", 
            data={
                "encryptedMsg":cryptogram,
                "filepath": filepath,
                "device_id": self.clientData["device_id"],
                "encr_time": (tock-tick)*(10**3),
                "keysize": 256
            }
        )
        if response.status_code == 200:
            return True
        else:
            return False


def iter(CURR_CLIENT_BASEURL):
    client = ClientECC(CURR_CLIENT_BASEURL, BASEURL_SERVER)
    if not client.clientRegistration():
        sys.exit(-1)

    if not client.keyExchange():
        sys.exit(-1)

    print("\nSending files!!")
    for dirpath, subdirs, files in os.walk(DATAPATH):
        for x in tqdm(files):
            filepath = os.path.join(dirpath, x)
            with open(filepath, "rb") as fin:
                res = client.sendMessage(fin.read(), x)
                if not res:
                    sys.exit(-1)
                    # print(f"File={filepath} sent successfully")


if __name__ == "__main__":

    global DATAPATH
    with open(CONFIGPATH, "r") as f:
        config = json.loads(f.read())

    if config["production"] == True:
        pd = "local"
    else:
        pd = "development"

    BASEURL_SERVER= config[pd]["server"]["BASEURL_SERVER"]
    BASEURL_CLIENT1 = config[pd]["client"]["BASEURL_CLIENT1"]
    BASEURL_CLIENT2 = config[pd]["client"]["BASEURL_CLIENT2"]
    DATAPATH = config[pd]["client"]["MSG_FOLDER_CLIENT1"]
    ITERATIONS = config[pd]["client"]["ECC_ITERATIONS_PER_FILE_CLIENT1"]

    for i in range(ITERATIONS):
        print("-"*10 + "ITERATION: " + str(i+1) + "-"*10)
        iter(BASEURL_CLIENT1)

