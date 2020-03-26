import requests

import secrets, binascii
from ecc import getCurve, encrypt_ECC, ecc_point_to_256_bit_key
import pickle
import base64
import time
import json
import random
import uuid
import sys
import os


curve = None
secretKey = None
BASEURL_CLIENT_DYN = None

BASEURL_SERVER= "http://023b8bc8.ngrok.io"
BASEURL_CLIENT1 = "http://127.0.0.1:8001"
BASEURL_CLIENT2 = "http://127.0.0.1:8002"

SECRET_FILE = "./secrets.json"

def knowMyGlobaldata():
    global curve
    global BASEURL_CLIENT_DYN
    data = {
        "device_id": uuid.uuid4(),
        "latitude": random.random()*500,
        "longitude": random.random()*500
    }
    response = requests.get(url = BASEURL_SERVER + "/globalparam/exchange/", params = data)
    curve = pickle.loads(base64.b64decode(response.json()["curve"]))
    with open(f"./{BASEURL_CLIENT_DYN[-1]}_secrets.json", "w") as f:
        secrets_ = {
            "curve": base64.b64encode(pickle.dumps(curve)).decode("utf-8"),
        }
        json.dump(secrets_, f)

def keyExchange():
    global secretKey
    global BASEURL_CLIENT_DYN
    # generate a
    privateKey = secrets.randbelow(curve.field.n)
    aG = privateKey*curve.g
    data = {
        "pr": base64.b64encode(pickle.dumps(aG)),
        "clientid": BASEURL_CLIENT_DYN
    }
    response = requests.post(url = BASEURL_CLIENT_DYN + "/keyexchange/", data=data)
    print("---------------------")

    bG = pickle.loads(base64.b64decode(response.json()["pr"]))
    secretKey = ecc_point_to_256_bit_key(bG*privateKey)

    with open(f"./{BASEURL_CLIENT_DYN[-1]}_secrets.json", "w") as f:
        secrets_ = {
            "curve": base64.b64encode(pickle.dumps(curve)).decode("utf-8"),
            "secretKey": base64.b64encode(secretKey).decode("utf-8")
        }
        json.dump(secrets_, f)

def sendMessage(msg):
    global BASEURL_CLIENT_DYN
    encryptedMsg = encrypt_ECC(msg.encode('utf-8'), secretKey)
    encryptedMsgObj = base64.b64encode(pickle.dumps(encryptedMsg)).decode("utf-8")
    response = requests.post(url = BASEURL_CLIENT_DYN+ "/send/msg/", data={"msg":encryptedMsgObj})
    if response.status_code == 200:
        return True
    else:
        return False


def sendPlainMessage(msg):
    global BASEURL_CLIENT_DYN
    response = requests.post(url = BASEURL_CLIENT_DYN + "/send/plainmsg/", 
        data={
            "msg":msg.encode('utf-8')
        }
    )
    print("Encrypted message", response.json()["msg"])
    return response.json()["msg"]



if __name__ == "__main__":
        
    # if len(sys.argv) == 2:
    #     BASEURL_CLIENT_DYN = sys.argv[2]

    if len(sys.argv) == 2: 
        if str(sys.argv[1])=="1":
            BASEURL_CLIENT_DYN=BASEURL_CLIENT2
        else:
            BASEURL_CLIENT_DYN=BASEURL_CLIENT1

    else:
        print("Please tell me which client")
        sys.exit(1)

    print("I am new here. Let me know my public parameters")
    knowMyGlobaldata()
    time.sleep(1)

    print("Got the public public data. Let's initiate key exchange protocol")
    keyExchange()
    time.sleep(1.5)

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
    