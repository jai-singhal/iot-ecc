import requests
import secrets, binascii
from utils import ecc
import pickle, time, json
import random
import uuid
import sys, os

clientData = {
    "device_id": None,
    "latitude": None,
    "longitude": None,
    "curve_name": None,
    "curve": None, 
    "secretKey": None
}

CURR_CLIENT_BASEURL = None

with open("./config.json", "r") as f:
    config = json.loads(f.read())

BASEURL_SERVER= config["local"]["server"]["BASEURL_SERVER"]
BASEURL_CLIENT1 = config["local"]["client"]["BASEURL_CLIENT1"]
BASEURL_CLIENT2 = config["local"]["client"]["BASEURL_CLIENT2"]


def clientRegistration():
    # send the client data
    clientData["device_id"] = str(uuid.uuid4())
    clientData["curve_name"] = ecc.get_curve_name(6) # random curve
    clientData["latitude"] = random.uniform(-180,180)
    clientData["longitude"] = random.uniform(-90, 90)

    response = requests.post(
        url = BASEURL_SERVER + "/ecc/post/client/register/", 
        data = json.dumps(clientData)
    )
    response = response.json()

    if response["status"]:
        print(response["message"])
        clientData["curve"] = ecc.getCurve(clientData["curve_name"])
        return True
    else:
        print("error:", response["error"])
        return False


def keyExchange():
    # generate a
    curve = clientData["curve"]
    if curve == None:
        print("Curve not found")
        return False

    privateKey = secrets.randbelow(curve.field.n)
    clientPublicKey = privateKey*curve.g # privKey*curve
    data = {
        "device_id": clientData["device_id"],
        "clipubKey": binascii.hexlify(pickle.dumps(clientPublicKey)),
    }

    response = requests.post(
        url = BASEURL_SERVER + "/ecc/post/keyexchange/", 
        data=data
    )
    response = response.json()
    if not response["status"]:
        print("error", response["error"])
        return False

    serverPubKey = pickle.loads(binascii.unhexlify(response["pubKey"]))
    clientData["secretKey"] = ecc.ecc_point_to_256_bit_key(serverPubKey*privateKey)
    return True


def sendMessage(msg):
    ct, nonce, tag = ecc.encrypt_AES_GCM(msg.encode('utf-8'), clientData["secretKey"])
    ct = binascii.hexlify(ct).decode("utf-8")
    tag = binascii.hexlify(tag).decode("utf-8")
    nonce = binascii.hexlify(nonce).decode("utf-8")

    cryptogram = tag + nonce + ct

    response = requests.post(
        url = BASEURL_SERVER + "/ecc/send/msg/", 
        data={
            "encryptedMsg":cryptogram,
            "device_id": clientData["device_id"]
        }
    )
    if response.status_code == 200:
        return True
    else:
        return False


if __name__ == "__main__":
        
    if len(sys.argv) == 2: 
        if str(sys.argv[1])=="1":
            CURR_CLIENT_BASEURL=BASEURL_CLIENT2
        else:
            CURR_CLIENT_BASEURL=BASEURL_CLIENT1

    else:
        print("Please tell me which client")
        sys.exit(1)

    print("I am new here. Let me send my public parameters")
    clientRegistration()

    print("Got the public public data. Let's initiate key exchange protocol")
    keyExchange()

    print("Done!!")
    print("--"*20 + "\n")

    print("Let's send the message")
    
    while True:
        msg = input("Enter the message to send: ")
        if(msg == "exit"):
            break
        res = sendMessage(msg)
        if res:
            print("Message sent successfully")

    # print("\n\nLet's send the plain message, without encryption")
    # msg = input("Enter the message to send: ")
    # encrypted = sendPlainMessage(msg)
    # response = requests.post(url = BASEURL_SERVER+ "/send/msg/", data={"msg":encrypted})
    # print("Message got is: ", response.json()["msg"])
    