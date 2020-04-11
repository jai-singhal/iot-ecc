import requests
import secrets, binascii
from utils import ecc
import pickle, time, json
import random
import uuid
import sys, os




class Client():
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
            url = self.BASEURL_SERVER + "/ecc/post/client/register/", 
            data = json.dumps(self.clientData)
        )
        response = response.json()

        if response["status"]:
            print(response["message"])
            self.clientData["curve"] = ecc.getCurve(self.clientData["curve_name"])
            return True
        else:
            print("error:", response["error"])
            return False


    def keyExchange(self):
        # generate a
        curve = self.clientData["curve"]
        if curve == None:
            print("Curve not found")
            return False

        privateKey = secrets.randbelow(curve.field.n)
        clientPublicKey = privateKey*curve.g # privKey*curve
        data = {
            "device_id": self.clientData["device_id"],
            "clipubKey": binascii.hexlify(pickle.dumps(clientPublicKey)),
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


    def sendMessage(self, msg):
        ct, nonce, tag = ecc.encrypt_AES_GCM(
            msg.encode('utf-8'), 
            self.clientData["secretKey"]
        )
        ct = binascii.hexlify(ct).decode("utf-8")
        tag = binascii.hexlify(tag).decode("utf-8")
        nonce = binascii.hexlify(nonce).decode("utf-8")

        cryptogram = tag + nonce + ct

        response = requests.post(
            url = self.BASEURL_SERVER + "/ecc/send/msg/", 
            data={
                "encryptedMsg":cryptogram,
                "device_id": self.clientData["device_id"]
            }
        )
        if response.status_code == 200:
            return True
        else:
            return False


if __name__ == "__main__":

    with open("./config.json", "r") as f:
        config = json.loads(f.read())

    if config["production"] == True:
        pd = "local"
    else:
        pd = "development"

    BASEURL_SERVER= config[pd]["server"]["BASEURL_SERVER"]
    BASEURL_CLIENT1 = config[pd]["client"]["BASEURL_CLIENT1"]
    BASEURL_CLIENT2 = config[pd]["client"]["BASEURL_CLIENT2"]


    if len(sys.argv) == 2: 
        if str(sys.argv[1])=="1":
            CURR_CLIENT_BASEURL=BASEURL_CLIENT1
        else:
            CURR_CLIENT_BASEURL=BASEURL_CLIENT2

    else:
        print("Please tell me which client")
        sys.exit(1)

    client = Client(CURR_CLIENT_BASEURL, BASEURL_SERVER)

    print("I am new here. Let me send my public parameters")
    if client.clientRegistration():
        print("Got the public public data. Let's initiate key exchange protocol")
    else:
        sys.exit(-1)

    if client.keyExchange():
        print("Done!!")
    else:
        sys.exit(-1)

    print("Let's send the message")
    
    while True:
        msg = input("Enter the message to send: ")
        if(msg == "exit"):
            break
        res = client.sendMessage(msg)
        if res:
            print("Message sent successfully")
