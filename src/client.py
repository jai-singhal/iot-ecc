import requests
import secrets, binascii
from ecc import getCurve, encrypt_ECC, ecc_point_to_256_bit_key
import pickle
import base64
import time
import random
import uuid

curve = None
secretKey = None

BASEURL = "http://023b8bc8.ngrok.io"


def knowMyGlobalParams():
    global curve
    params = {
        "device_id": uuid.uuid4(),
        "latitude": random.random()*500,
        "longitude": random.random()*500
    }
    response = requests.get(url = BASEURL + "/globalparam/exchange/", params = params)
    curve = pickle.loads(base64.b64decode(response.json()["curve"]))


def keyExchange():
    global secretKey
    # generate a
    privateKey = secrets.randbelow(curve.field.n)
    aG = privateKey*curve.g
    params = {
        "pr":  base64.b64encode(pickle.dumps(aG))
    }
    response = requests.post(url = BASEURL + "/keyexchange/", params=params)
    bG = pickle.loads(base64.b64decode(response.json()["pr"]))
    secretKey = ecc_point_to_256_bit_key(bG*privateKey)


def sendMessage(msg):
    encryptedMsg = encrypt_ECC(msg.encode('utf-8'), secretKey)
    encryptedMsgObj = base64.b64encode(pickle.dumps(encryptedMsg)).decode("utf-8")
    response = requests.post(url = BASEURL + "/send/msg/", params={"msg":encryptedMsgObj})
    if response.status_code == 200:
        return True
    else:
        return False


def sendPlainMessage(msg):
    response = requests.post(url = BASEURL + "/send/plainmsg/", 
        params={
            "msg":msg.encode('utf-8')
        }
    )
    print("Encrypted message", response.json()["msg"])
    return response.json()["msg"]


if __name__ == "__main__":
    print("I am new here. Let me know my public parameters")
    knowMyGlobalParams()
    time.sleep(1)

    print("Got the public public params. Let's initiate key exchange protocol")
    keyExchange()
    time.sleep(1.5)

    print("Done!!")
    print("--"*20 + "\n")

    print("Let's send the message")
    msg = input("Enter the message to send: ")
    res = sendMessage(msg)
    if res:
        print("Message sent successfully")

    print("\n\nLet's send the plain message, without encryption")
    msg = input("Enter the message to send: ")
    encrypted = sendPlainMessage(msg)
    response = requests.post(url = BASEURL + "/send/msg/", params={"msg":encrypted})
    print("Message got is: ", response.json()["msg"])
    